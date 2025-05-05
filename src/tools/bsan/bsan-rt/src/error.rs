use core::fmt::Display;

pub type Result<T> = core::result::Result<T, BsanError>;

#[derive(Debug, Clone)]
pub enum BsanError {
    ShadowStackOverflow,
}

impl Display for BsanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BsanError::ShadowStackOverflow => write!(f, "Shadow stack overflow"),
        }
    }
}
