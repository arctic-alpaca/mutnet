use crate::error::{UnexpectedBufferEndError, WrongChecksumError};

use core::fmt::{Debug, Display, Formatter};

#[cfg(all(feature = "error_trait", not(feature = "std")))]
use core::error;

#[cfg(feature = "std")]
use std::error;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ParseTcpError {
    UnexpectedBufferEnd(UnexpectedBufferEndError),
    WrongChecksum(WrongChecksumError),
    DataOffsetHeaderValueTooSmall { data_offset_header: usize },
}

impl From<UnexpectedBufferEndError> for ParseTcpError {
    #[inline]
    fn from(value: UnexpectedBufferEndError) -> Self {
        Self::UnexpectedBufferEnd(value)
    }
}

impl From<WrongChecksumError> for ParseTcpError {
    #[inline]
    fn from(value: WrongChecksumError) -> Self {
        Self::WrongChecksum(value)
    }
}

impl Display for ParseTcpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedBufferEnd(err) => {
                write!(f, "{err}")
            }
            Self::WrongChecksum(err) => {
                write!(f, "{err}")
            }
            Self::DataOffsetHeaderValueTooSmall { data_offset_header } => {
                write!(
                    f,
                    "Data offset header value invalid, expected to be between 5 and 20 (inclusive): {data_offset_header}"
                )
            }
        }
    }
}

#[cfg(feature = "error_trait")]
impl error::Error for ParseTcpError {}
