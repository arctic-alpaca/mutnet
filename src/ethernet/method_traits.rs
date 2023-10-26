use crate::addresses::mac::MacAddress;
use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderInformation, HeaderManipulation, Layer,
};
use crate::ether_type::{EtherType, NoRecognizedEtherTypeError};
use core::ops::Range;

pub(crate) const DESTINATION_MAC: Range<usize> = 0..6;
pub(crate) const SOURCE_MAC: Range<usize> = 6..12;
pub(crate) const ETHER_TYPE: Range<usize> = 12..14;

pub(crate) const HEADER_MIN_LEN: usize = 14;

pub(crate) const LAYER: Layer = Layer::EthernetII;

// Length manipulating methods: None

pub trait EthernetMethods: HeaderInformation + BufferAccess {
    #[inline]
    fn ethernet_destination(&self) -> MacAddress {
        self.data_buffer_starting_at_header(LAYER)[DESTINATION_MAC]
            .try_into()
            .unwrap()
    }

    #[inline]
    fn ethernet_source(&self) -> MacAddress {
        self.data_buffer_starting_at_header(LAYER)[SOURCE_MAC]
            .try_into()
            .unwrap()
    }

    #[inline]
    fn ethernet_ether_type(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[ETHER_TYPE]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn ethernet_typed_ether_type(&self) -> Result<EtherType, NoRecognizedEtherTypeError> {
        self.ethernet_ether_type().try_into()
    }
}

pub trait EthernetMethodsMut:
    EthernetMethods + BufferAccessMut + HeaderManipulation + Sized
{
    #[inline]
    fn set_ethernet_destination(&mut self, mac_addr: &MacAddress) {
        self.data_buffer_starting_at_header_mut(LAYER)[DESTINATION_MAC].copy_from_slice(mac_addr)
    }

    #[inline]
    fn set_ethernet_source(&mut self, mac_addr: &MacAddress) {
        self.data_buffer_starting_at_header_mut(LAYER)[SOURCE_MAC].copy_from_slice(mac_addr)
    }

    #[inline]
    fn set_ethernet_ether_type(&mut self, ether_type: EtherType) {
        self.data_buffer_starting_at_header_mut(LAYER)[ETHER_TYPE]
            .copy_from_slice(&(ether_type as u16).to_be_bytes())
    }
}
