use crate::addresses::ipv4::Ipv4Address;
use crate::addresses::mac::MacAddress;
use crate::data_buffer::traits::{BufferAccess, BufferAccessMut, HeaderManipulation, Layer};
use crate::typed_protocol_headers::{EtherType, UnrecognizedEtherTypeError};
use crate::typed_protocol_headers::{OperationCode, UnrecognizedOperationCodeError};
use core::ops::Range;

pub(crate) const HARDWARE_TYPE: Range<usize> = 0..2;
pub(crate) const PROTOCOL_TYPE: Range<usize> = 2..4;
pub(crate) const HARDWARE_ADDRESS_LENGTH: usize = 4;
pub(crate) const PROTOCOL_ADDRESS_LENGTH: usize = 5;
pub(crate) const OPERATION_CODE: Range<usize> = 6..8;
pub(crate) const SENDER_HARDWARE_ADDRESS: Range<usize> = 8..14;
pub(crate) const SENDER_PROTOCOL_ADDRESS: Range<usize> = 14..18;
pub(crate) const TARGET_HARDWARE_ADDRESS: Range<usize> = 18..24;
pub(crate) const TARGET_PROTOCOL_ADDRESS: Range<usize> = 24..28;

// 2 bytes hardware type
// 2 bytes protocol type
// 1 byte hardware address length
// 1 byte protocol address length
// 2 bytes operation code
// 6 bytes sender hardware address (MAC addr)
// 4 bytes sender protocol address (IPv4 addr)
// 6 bytes target hardware address (MAC addr)
// 4 bytes target protocol address (IPv4 addr)
// 28 bytes
pub(crate) const HEADER_MIN_LEN: usize = 28;

pub(crate) const LAYER: Layer = Layer::Arp;

// Length manipulating methods: None

pub trait ArpMethods: BufferAccess {
    #[inline]
    fn arp_hardware_type(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, HARDWARE_TYPE))
    }

    #[inline]
    fn arp_protocol_type(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, PROTOCOL_TYPE))
    }

    #[inline]
    fn arp_typed_protocol_type(&self) -> Result<EtherType, UnrecognizedEtherTypeError> {
        self.arp_protocol_type().try_into()
    }

    #[inline]
    fn arp_operation_code(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, OPERATION_CODE))
    }

    #[inline]
    fn arp_typed_operation_code(&self) -> Result<OperationCode, UnrecognizedOperationCodeError> {
        self.arp_operation_code().try_into()
    }

    #[inline]
    fn arp_hardware_address_length(&self) -> u8 {
        self.read_value(LAYER, HARDWARE_ADDRESS_LENGTH)
    }

    #[inline]
    fn arp_protocol_address_length(&self) -> u8 {
        self.read_value(LAYER, PROTOCOL_ADDRESS_LENGTH)
    }

    #[inline]
    fn arp_sender_hardware_address(&self) -> MacAddress {
        self.read_array(LAYER, SENDER_HARDWARE_ADDRESS)
    }

    #[inline]
    fn arp_sender_protocol_address(&self) -> Ipv4Address {
        self.read_array(LAYER, SENDER_PROTOCOL_ADDRESS)
    }

    #[inline]
    fn arp_target_hardware_address(&self) -> MacAddress {
        self.read_array(LAYER, TARGET_HARDWARE_ADDRESS)
    }

    #[inline]
    fn arp_target_protocol_address(&self) -> Ipv4Address {
        self.read_array(LAYER, TARGET_PROTOCOL_ADDRESS)
    }
}

pub trait ArpMethodsMut: ArpMethods + BufferAccessMut + HeaderManipulation + Sized {
    #[inline]
    fn set_arp_operation_code(&mut self, operation_code: OperationCode) {
        self.write_slice(
            LAYER,
            OPERATION_CODE,
            &(operation_code as u16).to_be_bytes(),
        );
    }

    #[inline]
    fn set_arp_sender_hardware_address(&mut self, sender_addr: &MacAddress) {
        self.write_slice(LAYER, SENDER_HARDWARE_ADDRESS, sender_addr);
    }

    #[inline]
    fn set_arp_sender_protocol_address(&mut self, sender_addr: &Ipv4Address) {
        self.write_slice(LAYER, SENDER_PROTOCOL_ADDRESS, sender_addr);
    }

    #[inline]
    fn set_arp_target_hardware_address(&mut self, target_addr: &MacAddress) {
        self.write_slice(LAYER, TARGET_HARDWARE_ADDRESS, target_addr);
    }

    #[inline]
    fn set_arp_target_protocol_address(&mut self, target_addr: &Ipv4Address) {
        self.write_slice(LAYER, TARGET_PROTOCOL_ADDRESS, target_addr);
    }
}
