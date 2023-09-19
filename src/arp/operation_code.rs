#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[repr(u16)]
pub enum OperationCode {
    Request = 1,
    Reply = 2,
}
