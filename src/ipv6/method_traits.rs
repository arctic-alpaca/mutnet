//! IPv6 access and manipulation methods.

use crate::addresses::ipv6::Ipv6Addr;
use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderManipulation, HeaderMetadata, Layer,
};
use crate::ipv6::SetPayloadLengthError;
use crate::typed_protocol_headers::{
    InternetProtocolNumber, UnrecognizedInternetProtocolNumberError,
};
use core::ops::Range;

pub(crate) const VERSION_BYTE: usize = 0;
pub(crate) const VERSION_SHIFT: usize = 4;
pub(crate) const TRAFFIC_CLASS: Range<usize> = 0..2;
pub(crate) const TRAFFIC_CLASS_MASK_WITHOUT_SURROUNDING_DATA: u16 = 0x0F_F0;
pub(crate) const TRAFFIC_CLASS_SHIFT: usize = 4;
/// Includes more data than required but simplifies reading a u32 and masking it.
pub(crate) const FLOW_LABEL_WITH_PREPENDED_DATA: Range<usize> = 0..4;
pub(crate) const FLOW_LABEL_MASK: u32 = 0x00_0F_FF_FF;
pub(crate) const PAYLOAD_LENGTH: Range<usize> = 4..6;
pub(crate) const NEXT_HEADER: usize = 6;
pub(crate) const HOP_LIMIT: usize = 7;
pub(crate) const SOURCE: Range<usize> = 8..24;
pub(crate) const DESTINATION: Range<usize> = 24..40;

pub(crate) const HEADER_MIN_LEN: usize = 40;

pub(crate) const LAYER: Layer = Layer::Ipv6;

// Length manipulating methods:
// - set_ipv6_payload_length (has proof)

/// Methods available for [`DataBuffer`](crate::data_buffer::DataBuffer) containing an
/// [`Ipv6`](crate::ipv6::Ipv6) header.
#[allow(private_bounds)]
pub trait Ipv6Methods: HeaderMetadata + BufferAccess {
    /// Returns the IPv6 version.
    #[inline]
    fn ipv6_version(&self) -> u8 {
        self.read_value(LAYER, VERSION_BYTE) >> VERSION_SHIFT
    }

    /// Returns the IPv6 traffic class.
    #[inline]
    fn ipv6_traffic_class(&self) -> u8 {
        let traffic_class_with_surrounding_data =
            u16::from_be_bytes(self.read_array(LAYER, TRAFFIC_CLASS));
        (traffic_class_with_surrounding_data >> 4) as u8
    }

    /// Returns the IPv6 flow label.
    #[inline]
    fn ipv6_flow_label(&self) -> u32 {
        let flow_label_with_prepended_data =
            u32::from_be_bytes(self.read_array(LAYER, FLOW_LABEL_WITH_PREPENDED_DATA));
        flow_label_with_prepended_data & FLOW_LABEL_MASK
    }

    /// Returns the IPv6 payload length.
    #[inline]
    fn ipv6_payload_length(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, PAYLOAD_LENGTH))
    }

    /// Returns the IPv6 next header.
    #[inline]
    fn ipv6_next_header(&self) -> u8 {
        self.read_value(LAYER, NEXT_HEADER)
    }

    /// Returns the IPv6 next header as [`InternetProtocolNumber`].
    ///
    /// # Errors
    /// Returns an error if the internet protocol number is not recognized.
    #[inline]
    fn ipv6_typed_next_header(
        &self,
    ) -> Result<InternetProtocolNumber, UnrecognizedInternetProtocolNumberError> {
        self.ipv6_next_header().try_into()
    }

    /// Returns the IPv6 hop limit.
    #[inline]
    fn ipv6_hop_limit(&self) -> u8 {
        self.read_value(LAYER, HOP_LIMIT)
    }

    /// Returns the IPv6 source.
    #[inline]
    fn ipv6_source(&self) -> Ipv6Addr {
        self.read_array(LAYER, SOURCE)
    }

    /// Returns the IPv6 destination.
    #[inline]
    fn ipv6_destination(&self) -> Ipv6Addr {
        self.read_array(LAYER, DESTINATION)
    }
}

/// Methods available for [`DataBuffer`](crate::data_buffer::DataBuffer) containing an
/// [`Ipv6`](crate::ipv6::Ipv6) header and wrapping a mutable data buffer.
#[allow(private_bounds)]
pub trait Ipv6MethodsMut: HeaderManipulation + BufferAccessMut + Ipv6Methods + Sized {
    /// Sets the IPv6 traffic class.
    #[inline]
    fn set_ipv6_traffic_class(&mut self, traffic_class: u8) {
        let mut new_traffic_class_with_surrounding_data =
            u16::from_be_bytes(self.read_array(LAYER, TRAFFIC_CLASS));
        new_traffic_class_with_surrounding_data &= !TRAFFIC_CLASS_MASK_WITHOUT_SURROUNDING_DATA;
        new_traffic_class_with_surrounding_data |= u16::from(traffic_class) << TRAFFIC_CLASS_SHIFT;
        self.write_slice(
            LAYER,
            TRAFFIC_CLASS,
            &new_traffic_class_with_surrounding_data.to_be_bytes(),
        );
    }

    /// Sets the IPv6 flow label.
    ///
    /// Ignores the 12 most significant bits of `flow_label` because the field is only 20 bits long.  
    #[inline]
    fn set_ipv6_flow_label(&mut self, mut flow_label: u32) {
        flow_label &= FLOW_LABEL_MASK;
        // Takes first two bytes of the IPv6 header (version, traffic class and first bit of flow
        // label) and keeps only non-flow label bytes.
        flow_label |=
            (u32::from(u16::from_be_bytes(self.read_array(LAYER, 0..2))) << 16) & !FLOW_LABEL_MASK;

        self.write_slice(
            LAYER,
            FLOW_LABEL_WITH_PREPENDED_DATA,
            &flow_label.to_be_bytes(),
        );
    }

    /// Sets the IPv6 payload length.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `payload_length` exceeds the available space.
    /// - the length of `payload_length` would cause already parsed upper layers to be cut of.
    #[inline]
    fn set_ipv6_payload_length(
        &mut self,
        payload_length: u16,
    ) -> Result<(), SetPayloadLengthError> {
        let payload_length_usize = usize::from(payload_length);
        let data_length = self.header_start_offset(LAYER) + HEADER_MIN_LEN + payload_length_usize;

        // Don't allow cutting already parsed upper layers
        if self.layer() != LAYER {
            let intermediate_upper_headers_length = self.header_start_offset(self.layer())
                - self.header_start_offset(LAYER)
                - HEADER_MIN_LEN;

            let highest_header_length = self.header_length(self.layer());
            if payload_length_usize < intermediate_upper_headers_length + highest_header_length {
                return Err(SetPayloadLengthError::CannotCutUpperLayerHeader);
            }
        }

        self.set_data_length(data_length, self.buffer_length())?;

        self.write_slice(LAYER, PAYLOAD_LENGTH, &payload_length.to_be_bytes());
        Ok(())
    }

    /// Sets the IPv6 next header.
    #[inline]
    fn set_ipv6_next_header(&mut self, next_header: u8) {
        self.write_value(LAYER, NEXT_HEADER, next_header);
    }

    /// Sets the IPv6 hop limit.
    #[inline]
    fn set_ipv6_hop_limit(&mut self, hop_limit: u8) {
        self.write_value(LAYER, HOP_LIMIT, hop_limit);
    }

    /// Sets the IPv6 source.
    #[inline]
    fn set_ipv6_source(&mut self, source: Ipv6Addr) {
        self.write_slice(LAYER, SOURCE, &source);
    }

    /// Sets the IPv6 destination.
    #[inline]
    fn set_ipv6_destination(&mut self, destination: Ipv6Addr) {
        self.write_slice(LAYER, DESTINATION, &destination);
    }
}

/// Allows updating the IPv6 length from other layers.
pub(crate) trait UpdateIpv6Length:
    HeaderManipulation + BufferAccessMut + Ipv6Methods + Sized
{
    #[inline]
    fn update_ipv6_length(&mut self) {
        let ipv6_length = self.data_length() - self.header_start_offset(LAYER) - HEADER_MIN_LEN;

        self.write_slice(LAYER, PAYLOAD_LENGTH, &(ipv6_length as u16).to_be_bytes());
    }
}
