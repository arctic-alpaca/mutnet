#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[repr(u16)]
pub enum OperationCode {
    Request = 1,
    Reply = 2,
}

impl core::fmt::Display for OperationCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

impl TryFrom<u16> for OperationCode {
    type Error = UnrecognizedOperationCodeError;

    #[inline]
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(OperationCode::Request),
            2 => Ok(OperationCode::Reply),
            _ => Err(UnrecognizedOperationCodeError {
                operation_code: value,
            }),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct UnrecognizedOperationCodeError {
    pub operation_code: u16,
}

impl core::fmt::Display for UnrecognizedOperationCodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "Unrecognized operation code, was: {:?}",
            self.operation_code
        ))
    }
}

#[cfg(all(feature = "error_trait", not(feature = "std")))]
impl core::error::Error for UnrecognizedOperationCodeError {}

#[cfg(feature = "std")]
impl std::error::Error for UnrecognizedOperationCodeError {}

#[cfg(kani)]
mod operation_code_verification {
    use super::*;

    #[kani::proof]
    fn operation_code_proof() {
        let try_value = kani::any::<u16>();
        match OperationCode::try_from(try_value) {
            Ok(enum_value) => {
                assert_eq!(enum_value as u16, try_value);
            }
            Err(err) => {
                assert_eq!(
                    UnrecognizedOperationCodeError {
                        operation_code: try_value
                    },
                    err
                );
            }
        }
    }
}
