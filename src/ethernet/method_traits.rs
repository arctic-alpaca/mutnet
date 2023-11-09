//! Ethernet II access and manipulation methods.

use crate::addresses::mac::MacAddress;
use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderManipulation, HeaderMetadata, Layer,
};
use crate::typed_protocol_headers::{EtherType, UnrecognizedEtherTypeError};
use core::ops::Range;

pub(crate) const DESTINATION_MAC: Range<usize> = 0..6;
pub(crate) const SOURCE_MAC: Range<usize> = 6..12;
pub(crate) const ETHER_TYPE: Range<usize> = 12..14;

pub(crate) const HEADER_MIN_LEN: usize = 14;

pub(crate) const LAYER: Layer = Layer::EthernetII;

// Length manipulating methods: None

/// Methods available for [`DataBuffer`](crate::data_buffer::DataBuffer) containing an
/// [`Eth`](crate::ethernet::Eth) header.
pub trait EthernetMethods: HeaderMetadata + BufferAccess {
    /// Returns the ethernet II destination.
    #[inline]
    fn ethernet_destination(&self) -> MacAddress {
        self.read_array(LAYER, DESTINATION_MAC)
    }

    /// Returns the ethernet II source.
    #[inline]
    fn ethernet_source(&self) -> MacAddress {
        self.read_array(LAYER, SOURCE_MAC)
    }

    /// Returns the ethernet II ether type.
    #[inline]
    fn ethernet_ether_type(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, ETHER_TYPE))
    }

    /// Returns the ethernet II ether type as [`EtherType`].
    ///
    /// # Errors
    /// Returns an error if the ether type is not recognized.
    #[inline]
    fn ethernet_typed_ether_type(&self) -> Result<EtherType, UnrecognizedEtherTypeError> {
        self.ethernet_ether_type().try_into()
    }
}

/// Methods available for [`DataBuffer`](crate::data_buffer::DataBuffer) containing an
/// [`Eth`](crate::ethernet::Eth) header and wrapping a mutable data buffer.
pub trait EthernetMethodsMut:
    EthernetMethods + BufferAccessMut + HeaderManipulation + Sized
{
    /// Sets the ethernet II destination.
    #[inline]
    fn set_ethernet_destination(&mut self, mac_addr: &MacAddress) {
        self.write_slice(LAYER, DESTINATION_MAC, mac_addr);
    }

    /// Sets the ethernet II source.
    #[inline]
    fn set_ethernet_source(&mut self, mac_addr: &MacAddress) {
        self.write_slice(LAYER, SOURCE_MAC, mac_addr);
    }

    /// Sets the ethernet II ether type.
    #[inline]
    fn set_ethernet_ether_type(&mut self, ether_type: EtherType) {
        self.write_slice(LAYER, ETHER_TYPE, &(ether_type as u16).to_be_bytes());
    }
}
