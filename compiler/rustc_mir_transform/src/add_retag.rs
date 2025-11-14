//! This pass adds validation calls (AcquireValid, ReleaseValid) where appropriate.
//! It has to be run really early, before transformations like inlining, because
//! introducing these calls *adds* UB -- so, conceptually, this pass is actually part
//! of MIR building, and only after this pass we think of the program has having the
//! normal MIR semantics.

use rustc_index::IndexSlice;
use rustc_middle::mir::*;
use rustc_middle::ty::{self, Ty, TyCtxt};

pub(super) struct AddRetag;

fn assignment_needs_retag<'tcx>(
    tcx: TyCtxt<'tcx>,
    local_decls: &IndexSlice<Local, LocalDecl<'tcx>>,
    place: &Place<'tcx>,
    rvalue: &Rvalue<'tcx>,
) -> Option<RetagKind> {
    match rvalue {
        // Creating a raw pointer from a reference or the deref of a Box requires
        // a retag under Stacked Borrows.
        Rvalue::RawPtr(_, place) => {
            // Using `is_box_global` here is a bit sketchy: if this code is
            // generic over the allocator, we'll not add a retag! This is a hack
            // to make Stacked Borrows compatible with custom allocator code.
            // It means the raw pointer inherits the tag of the box, which mostly works
            // but can sometimes lead to unexpected aliasing errors.
            // Long-term, we'll want to move to an aliasing model where "cast to
            // raw pointer" is a complete NOP, and then this will no longer be
            // an issue.
            let local_ty = local_decls[place.local].ty;
            if place.is_indirect_first_projection()
                && (local_ty.is_box_global(tcx) || local_ty.is_ref())
            {
                return Some(RetagKind::Raw);
            }
            None
        }
        Rvalue::Ref(_, borrow_kind, _) => {
            if borrow_kind.allows_two_phase_borrow() {
                Some(RetagKind::TwoPhase)
            } else {
                Some(RetagKind::Default)
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
        sess.opts.unstable_opts.mir_emit_retag || sess.opts.unstable_opts.codegen_emit_retag
    }

    fn run_pass(&self, tcx: TyCtxt<'tcx>, body: &mut Body<'tcx>) {
        // We need an `AllCallEdges` pass before we can do any work.
        super::add_call_guards::AllCallEdges.run_pass(tcx, body);

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
                                assignment_needs_retag(tcx, local_decls, place, rvalue)
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
            let mut offset = 0;
            for (statement_idx, dest_place, rvalue, retag_kind) in assign_info.drain(..) {
                if tcx.sess.opts.unstable_opts.codegen_emit_retag {
                    // Insert a retag after the statement.
                    let statement_idx: usize = statement_idx + offset;
                    let source_info =
                        body.basic_blocks[block].statements[statement_idx].source_info;

                    let mut statements: Vec<Statement<'tcx>> = Vec::new();

                    let dest_place: Place<'tcx> = if dest_place.is_indirect() {
                        let temp_dest_local_decl = LocalDecl::with_source_info(
                            tcx.mk_ty_from_kind(ty::RawPtr(
                                dest_place.ty(body.local_decls(), tcx).ty,
                                Mutability::Mut,
                            )),
                            source_info,
                        );

                        let temp_dest_local = body.local_decls.push(temp_dest_local_decl);
                        let temp_dest_place =
                            Place { local: temp_dest_local, projection: tcx.mk_place_elems(&[]) };

                        statements.push(Statement::new(
                            source_info,
                            StatementKind::Assign(Box::new((
                                temp_dest_place,
                                Rvalue::RawPtr(RawPtrKind::Mut, dest_place),
                            ))),
                        ));
                        temp_dest_place
                    } else {
                        dest_place
                    };

                    let temp_rvalue_local_decl = LocalDecl::with_source_info(
                        dest_place.ty(body.local_decls(), tcx).ty,
                        source_info,
                    );

                    let temp_rvalue_local = body.local_decls.push(temp_rvalue_local_decl);

                    let temp_rvalue_place =
                        Place { local: temp_rvalue_local, projection: tcx.mk_place_elems(&[]) };

                    statements.push(Statement::new(
                        source_info,
                        StatementKind::Assign(Box::new((temp_rvalue_place, rvalue.clone()))),
                    ));

                    statements.push(Statement::new(
                        source_info,
                        StatementKind::Retag(retag_kind, Box::new(temp_rvalue_place)),
                    ));

                    statements.push(Statement::new(
                        source_info,
                        StatementKind::Assign(Box::new((
                            dest_place,
                            Rvalue::Use(Operand::Move(temp_rvalue_place)),
                        ))),
                    ));

                    offset += statements.len() - 1;

                    let block_data = &mut body.basic_blocks_mut()[block];
                    block_data.statements.remove(statement_idx);
                    block_data.statements.splice(statement_idx..statement_idx, statements);
                } else {
                    let source_info =
                        body.basic_blocks[block].statements[statement_idx].source_info;
                    body.basic_blocks_mut()[block].statements.insert(
                        statement_idx + 1,
                        Statement::new(
                            source_info,
                            StatementKind::Retag(retag_kind, Box::new(dest_place)),
                        ),
                    );
                    offset += 1;
                }
            }
        }
    }

    fn is_required(&self) -> bool {
        true
    }
}
