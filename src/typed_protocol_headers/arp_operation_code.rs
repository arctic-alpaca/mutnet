//! Typed versions of ARP protocol header fields.

/// ARP packet operation code
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[repr(u16)]
pub enum OperationCode {
    /// Indicates request (1)
    Request = 1,
    /// Indicates reply (2)
    Reply = 2,
}

impl core::fmt::Display for OperationCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{self:?}"))
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

/// Error returned by [`OperationCode::try_from()`].
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct UnrecognizedOperationCodeError {
    /// The unrecognized operation code.
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

impl core::error::Error for UnrecognizedOperationCodeError {}

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
