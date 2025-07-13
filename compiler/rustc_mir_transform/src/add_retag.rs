//! This pass adds validation calls (AcquireValid, ReleaseValid) where appropriate.
//! It has to be run really early, before transformations like inlining, because
//! introducing these calls *adds* UB -- so, conceptually, this pass is actually part
//! of MIR building, and only after this pass we think of the program has having the
//! normal MIR semantics.

use rustc_index::IndexSlice;
use rustc_middle::mir::*;
use rustc_middle::ty::{self, Ty, TyCtxt};
use rustc_target::spec::RetagMode;

pub(super) struct AddRetag;

fn assignment_needs_retag<'tcx>(
    tcx: TyCtxt<'tcx>,
    local_decls: &IndexSlice<Local, LocalDecl<'tcx>>,
    place: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
    mode: RetagMode,
) -> Option<RetagKind> {
    match rvalue {
        // Ptr-creating operations already do their own internal retagging, no
        // need to also add a retag statement. *Except* if we are deref'ing a
        // Box, because those get desugared to directly working with the inner
        // raw pointer! That's relevant for `RawPtr` as Miri otherwise makes it
        // a NOP when the original pointer is already raw.
        Rvalue::RawPtr(_mutbl, place) => {
            // Using `is_box_global` here is a bit sketchy: if this code is
            // generic over the allocator, we'll not add a retag! This is a hack
            // to make Stacked Borrows compatible with custom allocator code.
            // It means the raw pointer inherits the tag of the box, which mostly works
            // but can sometimes lead to unexpected aliasing errors.
            // Long-term, we'll want to move to an aliasing model where "cast to
            // raw pointer" is a complete NOP, and then this will no longer be
            // an issue.
            if place.is_indirect_first_projection()
                && local_decls[place.local].ty.is_box_global(tcx)
            {
                Some(RetagKind::Raw)
            } else {
                None
            }
        }
        Rvalue::Ref(_, borrow_kind, _) => {
            if matches!(mode, RetagMode::Full) {
                if borrow_kind.allows_two_phase_borrow() {
                    Some(RetagKind::TwoPhase)
                } else {
                    Some(RetagKind::Default)
                }
            } else {
                None
            }
        }
        _ => {
            if place_needs_retag(tcx, local_decls, place) {
                Some(RetagKind::Default)
            } else {
                None
            }
        }
    }
}

fn place_needs_retag<'tcx>(
    tcx: TyCtxt<'tcx>,
    local_decls: &IndexSlice<Local, LocalDecl<'tcx>>,
    place: &Place<'tcx>,
) -> bool {
    // We're not really interested in stores to "outside" locations, they are hard to keep
    // track of anyway.
    !place.is_indirect_first_projection()
        && may_contain_reference(place.ty(local_decls, tcx).ty, /*depth*/ 3, tcx)
        && !local_decls[place.local].is_deref_temp()
}

/// Determine whether this type may contain a reference (or box), and thus needs retagging.
/// We will only recurse `depth` times into Tuples/ADTs to bound the cost of this.
fn may_contain_reference<'tcx>(ty: Ty<'tcx>, depth: u32, tcx: TyCtxt<'tcx>) -> bool {
    match ty.kind() {
        // Primitive types that are not references
        ty::Bool
        | ty::Char
        | ty::Float(_)
        | ty::Int(_)
        | ty::Uint(_)
        | ty::RawPtr(..)
        | ty::FnPtr(..)
        | ty::Str
        | ty::FnDef(..)
        | ty::Never => false,
        // References and Boxes (`noalias` sources)
        ty::Ref(..) => true,
        ty::Adt(..) if ty.is_box() => true,
        // Compound types: recurse
        ty::Array(ty, _) | ty::Slice(ty) => {
            // This does not branch so we keep the depth the same.
            may_contain_reference(*ty, depth, tcx)
        }
        ty::Tuple(tys) => {
            depth == 0 || tys.iter().any(|ty| may_contain_reference(ty, depth - 1, tcx))
        }
        ty::Adt(adt, args) => {
            depth == 0
                || adt.variants().iter().any(|v| {
                    v.fields.iter().any(|f| may_contain_reference(f.ty(tcx, args), depth - 1, tcx))
                })
        }
        // Conservative fallback
        _ => true,
    }
}

impl<'tcx> crate::MirPass<'tcx> for AddRetag {
    fn is_enabled(&self, sess: &rustc_session::Session) -> bool {
        sess.opts.unstable_opts.mir_emit_retag.is_some()
            || sess.opts.unstable_opts.codegen_emit_retag
    }

    fn run_pass(&self, tcx: TyCtxt<'tcx>, body: &mut Body<'tcx>) {
        // We need an `AllCallEdges` pass before we can do any work.
        super::add_call_guards::AllCallEdges.run_pass(tcx, body);

        let retag_mode =
            tcx.sess.opts.unstable_opts.mir_emit_retag.expect("A retag mode should be present.");

        let basic_blocks = body.basic_blocks.as_mut();
        let local_decls = &body.local_decls;
        let needs_retag = |place: &Place<'tcx>| {
            // We're not really interested in stores to "outside" locations, they are hard to keep
            // track of anyway.
            !place.is_indirect_first_projection()
                && may_contain_reference(place.ty(&*local_decls, tcx).ty, /*depth*/ 3, tcx)
                && !local_decls[place.local].is_deref_temp()
        };

        // PART 1
        // Retag arguments at the beginning of the start block.
        {
            // Gather all arguments, skip return value.
            let places = local_decls.iter_enumerated().skip(1).take(body.arg_count).filter_map(
                |(local, decl)| {
                    let place = Place::from(local);
                    needs_retag(&place).then_some((place, decl.source_info))
                },
            );

            // Emit their retags.
            basic_blocks[START_BLOCK].statements.splice(
                0..0,
                places.map(|(place, source_info)| {
                    Statement::new(
                        source_info,
                        StatementKind::Retag(RetagKind::FnEntry, Box::new(place)),
                    )
                }),
            );
        }

        // PART 2
        // Retag return values of functions.
        // We collect the return destinations because we cannot mutate while iterating.
        let returns = basic_blocks
            .iter_mut()
            .filter_map(|block_data| {
                match block_data.terminator().kind {
                    TerminatorKind::Call { target: Some(target), destination, .. }
                        if needs_retag(&destination) =>
                    {
                        // Remember the return destination for later
                        Some((block_data.terminator().source_info, destination, target))
                    }

                    // `Drop` is also a call, but it doesn't return anything so we are good.
                    TerminatorKind::Drop { .. } => None,
                    // Not a block ending in a Call -> ignore.
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        // Now we go over the returns we collected to retag the return values.
        for (source_info, dest_place, dest_block) in returns {
            basic_blocks[dest_block].statements.insert(
                0,
                Statement::new(
                    source_info,
                    StatementKind::Retag(RetagKind::Default, Box::new(dest_place)),
                ),
            );
        }

        // PART 3
        // Add retags for assignments.
        // Similar to returns, we need to collect the index for each assignment
        // because we cannot mutate while iterating.
        let mut assignments = basic_blocks
            .indices()
            .map(|block| {
                let assign_info = basic_blocks[block]
                    .statements
                    .iter()
                    .enumerate()
                    .filter_map(move |(idx, statement)| {
                        if let StatementKind::Assign(box (ref place, ref rvalue)) = statement.kind
                            && let Some(retag_kind) =
                                assignment_needs_retag(tcx, local_decls, place, rvalue, retag_mode)
                        {
                            Some((idx, *place, rvalue.clone(), retag_kind))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                (block, assign_info)
            })
            .collect::<Vec<_>>();

        for (block, mut assign_info) in assignments.drain(..) {
            for (offset, (statement_idx, place, rvalue, retag_kind)) in
                assign_info.drain(..).enumerate()
            {
                if tcx.sess.opts.unstable_opts.codegen_emit_retag {
                    // Insert a retag after the statement.
                    let statement_idx: usize = statement_idx + offset * 2;
                    let source_info =
                        body.basic_blocks[block].statements[statement_idx].source_info;

                    let local_decl = LocalDecl::with_source_info(
                        place.ty(body.local_decls(), tcx).ty,
                        source_info,
                    );
                    let local = body.local_decls.push(local_decl);
                    let temp_local_place = Place { local, projection: tcx.mk_place_elems(&[]) };

                    let block_data = &mut body.basic_blocks_mut()[block];

                    block_data.statements[statement_idx] = Statement::new(
                        source_info,
                        StatementKind::Assign(Box::new((
                            place,
                            Rvalue::Use(Operand::Move(temp_local_place)),
                        ))),
                    );

                    block_data.statements.insert(
                        statement_idx,
                        Statement::new(
                            source_info,
                            StatementKind::Retag(retag_kind, Box::new(temp_local_place)),
                        ),
                    );

                    block_data.statements.insert(
                        statement_idx,
                        Statement::new(
                            source_info,
                            StatementKind::Assign(Box::new((temp_local_place, rvalue.clone()))),
                        ),
                    );
                } else {
                    let source_info =
                        body.basic_blocks[block].statements[statement_idx].source_info;
                    body.basic_blocks_mut()[block].statements.insert(
                        statement_idx + 1,
                        Statement::new(
                            source_info,
                            StatementKind::Retag(retag_kind, Box::new(place)),
                        ),
                    );
                }
            }
        }
    }

    fn is_required(&self) -> bool {
        true
    }
}
