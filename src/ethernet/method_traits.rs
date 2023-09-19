use crate::addresses::mac::MacAddress;
use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderInformation, HeaderManipulation, Layer,
};
use crate::ether_type::{EtherType, NoRecognizedEtherTypeError};

pub(crate) static DESTINATION_MAC_START: usize = 0;
pub(crate) static DESTINATION_MAC_END: usize = 6;
pub(crate) static SOURCE_MAC_START: usize = 6;
pub(crate) static SOURCE_MAC_END: usize = 12;
pub(crate) static ETHER_TYPE_START: usize = 12;
pub(crate) static ETHER_TYPE_END: usize = 14;

pub(crate) static HEADER_MIN_LEN: usize = 14;

pub(crate) static LAYER: Layer = Layer::EthernetII;

// Length manipulating methods: None

pub trait EthernetMethods: HeaderInformation + BufferAccess {
    #[inline]
    fn ethernet_destination(&self) -> MacAddress {
        self.data_buffer_starting_at_header(LAYER)[DESTINATION_MAC_START..DESTINATION_MAC_END]
            .try_into()
            .unwrap()
    }

    #[inline]
    fn ethernet_source(&self) -> MacAddress {
        self.data_buffer_starting_at_header(LAYER)[SOURCE_MAC_START..SOURCE_MAC_END]
            .try_into()
            .unwrap()
    }

    #[inline]
    fn ethernet_ether_type(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[ETHER_TYPE_START..ETHER_TYPE_END]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn ethernet_typed_ether_type(&self) -> Result<EtherType, NoRecognizedEtherTypeError> {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[ETHER_TYPE_START..ETHER_TYPE_END]
                .try_into()
                .unwrap(),
        )
        .try_into()
    }
}

pub trait EthernetMethodsMut:
    EthernetMethods + BufferAccessMut + HeaderManipulation + Sized
{
    #[inline]
    fn set_ethernet_destination(&mut self, mac_addr: &MacAddress) {
        self.data_buffer_starting_at_header_mut(LAYER)[DESTINATION_MAC_START..DESTINATION_MAC_END]
            .copy_from_slice(mac_addr)
    }

    #[inline]
    fn set_ethernet_source(&mut self, mac_addr: &MacAddress) {
        self.data_buffer_starting_at_header_mut(LAYER)[SOURCE_MAC_START..SOURCE_MAC_END]
            .copy_from_slice(mac_addr)
    }

    #[inline]
    fn set_ethernet_ether_type(&mut self, ether_type: EtherType) {
        self.data_buffer_starting_at_header_mut(LAYER)[ETHER_TYPE_START..ETHER_TYPE_END]
            .copy_from_slice(&(ether_type as u16).to_be_bytes())
    }
}
