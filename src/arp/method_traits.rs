use crate::addresses::ipv4::Ipv4Address;
use crate::addresses::mac::MacAddress;
use crate::arp::{NoRecognizedOperationCodeError, OperationCode};
use crate::data_buffer::traits::{BufferAccess, BufferAccessMut, HeaderManipulation, Layer};
use crate::ether_type::{EtherType, NoRecognizedEtherTypeError};
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
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[HARDWARE_TYPE]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn arp_protocol_type(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[PROTOCOL_TYPE]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn arp_typed_protocol_type(&self) -> Result<EtherType, NoRecognizedEtherTypeError> {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[PROTOCOL_TYPE]
                .try_into()
                .unwrap(),
        )
        .try_into()
    }

    #[inline]
    fn arp_operation_code(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[OPERATION_CODE]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn arp_typed_operation_code(&self) -> Result<OperationCode, NoRecognizedOperationCodeError> {
        match self.arp_operation_code() {
            1 => Ok(OperationCode::Request),
            2 => Ok(OperationCode::Reply),
            operation_code_bytes => Err(NoRecognizedOperationCodeError {
                operation_code: operation_code_bytes,
            }),
        }
    }

    #[inline]
    fn arp_hardware_address_length(&self) -> u8 {
        self.data_buffer_starting_at_header(LAYER)[HARDWARE_ADDRESS_LENGTH]
    }

    #[inline]
    fn arp_protocol_address_length(&self) -> u8 {
        self.data_buffer_starting_at_header(LAYER)[PROTOCOL_ADDRESS_LENGTH]
    }

    #[inline]
    fn arp_sender_hardware_address(&self) -> MacAddress {
        self.data_buffer_starting_at_header(LAYER)[SENDER_HARDWARE_ADDRESS]
            .try_into()
            .unwrap()
    }

    #[inline]
    fn arp_sender_protocol_address(&self) -> Ipv4Address {
        self.data_buffer_starting_at_header(LAYER)[SENDER_PROTOCOL_ADDRESS]
            .try_into()
            .unwrap()
    }

    #[inline]
    fn arp_target_hardware_address(&self) -> MacAddress {
        self.data_buffer_starting_at_header(LAYER)[TARGET_HARDWARE_ADDRESS]
            .try_into()
            .unwrap()
    }

    #[inline]
    fn arp_target_protocol_address(&self) -> Ipv4Address {
        self.data_buffer_starting_at_header(LAYER)[TARGET_PROTOCOL_ADDRESS]
            .try_into()
            .unwrap()
    }
}

pub trait ArpMethodsMut: ArpMethods + BufferAccessMut + HeaderManipulation + Sized {
    #[inline]
    fn arp_set_operation_code(&mut self, operation_code: OperationCode) {
        self.data_buffer_starting_at_header_mut(LAYER)[OPERATION_CODE]
            .copy_from_slice(&(operation_code as u16).to_be_bytes())
    }

    #[inline]
    fn arp_set_sender_hardware_address(&mut self, sender_addr: &MacAddress) {
        self.data_buffer_starting_at_header_mut(LAYER)[SENDER_HARDWARE_ADDRESS]
            .copy_from_slice(sender_addr)
    }

    #[inline]
    fn arp_set_sender_protocol_address(&mut self, sender_addr: &Ipv4Address) {
        self.data_buffer_starting_at_header_mut(LAYER)[SENDER_PROTOCOL_ADDRESS]
            .copy_from_slice(sender_addr)
    }

    #[inline]
    fn arp_set_target_hardware_address(&mut self, target_addr: &MacAddress) {
        self.data_buffer_starting_at_header_mut(LAYER)[TARGET_HARDWARE_ADDRESS]
            .copy_from_slice(target_addr)
    }

    #[inline]
    fn arp_set_target_protocol_address(&mut self, target_addr: &Ipv4Address) {
        self.data_buffer_starting_at_header_mut(LAYER)[TARGET_PROTOCOL_ADDRESS]
            .copy_from_slice(target_addr)
    }
}
