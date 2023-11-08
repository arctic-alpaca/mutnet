//! UDP access and manipulation methods.

use crate::checksum::internet_checksum;
use crate::data_buffer::{
    BufferAccess, BufferAccessMut, HeaderManipulation, HeaderMetadata, Layer,
};
use crate::udp::SetLengthError;
use crate::utility_traits::{TcpUdpChecksum, UpdateIpLength};
use core::ops::Range;

pub(crate) const SOURCE_PORT: Range<usize> = 0..2;
pub(crate) const DESTINATION_PORT: Range<usize> = 2..4;
pub(crate) const LENGTH: Range<usize> = 4..6;
pub(crate) const CHECKSUM: Range<usize> = 6..8;

pub(crate) const HEADER_MIN_LEN: usize = 8;

pub(crate) const LAYER: Layer = Layer::Udp;

// Length manipulating methods:
// - set_udp_length (has proof)

/// Methods available for [`DataBuffer`](crate::data_buffer::DataBuffer) containing a
/// [`Udp`](crate::udp::Udp) header.
pub trait UdpMethods: HeaderMetadata + TcpUdpChecksum + BufferAccess {
    /// Returns the UDP source port.
    #[inline]
    fn udp_source_port(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, SOURCE_PORT))
    }

    /// Returns the UDP destination port.
    #[inline]
    fn udp_destination_port(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, DESTINATION_PORT))
    }

    /// Returns the UDP length.
    #[inline]
    fn udp_length(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, LENGTH))
    }

    /// Returns the UDP checksum.
    #[inline]
    fn udp_checksum(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, CHECKSUM))
    }

    /// Calculates and returns the UDP checksum.
    ///
    /// This takes lower layers into account.
    /// If there is an [`IPv4`](crate::ipv4::Ipv4) or [`IPv6`](crate::ipv6::Ipv6) layer present,
    /// the pseudo header will be included.
    /// If there is a [`NoPreviousHeader`](crate::no_previous_header::NoPreviousHeader) present,
    /// the pseudo header is set to zero.
    #[inline]
    fn udp_calculate_checksum(&self) -> u16 {
        let pseudoheader_checksum = self.pseudoheader_checksum();

        let payload_end = usize::from(self.udp_length());
        internet_checksum::<4>(
            pseudoheader_checksum,
            &self.data_buffer_starting_at_header(LAYER)[..payload_end],
        )
    }
}

/// Methods available for [`DataBuffer`](crate::data_buffer::DataBuffer) containing a
/// [`Udp`](crate::tcp::Udp) header and wrapping a mutable data buffer.
pub trait UdpMethodsMut:
    HeaderMetadata
    + HeaderManipulation
    + BufferAccessMut
    + UdpMethods
    + TcpUdpChecksum
    + UpdateIpLength
    + Sized
{
    /// Sets the UDP source port.
    #[inline]
    fn set_udp_source_port(&mut self, port: u16) {
        self.write_slice(LAYER, SOURCE_PORT, &port.to_be_bytes());
    }

    /// Sets the UDP destination port.
    #[inline]
    fn set_udp_destination_port(&mut self, port: u16) {
        self.write_slice(LAYER, DESTINATION_PORT, &port.to_be_bytes());
    }

    /// Sets the UDP length.
    ///
    /// This takes lower layers into account.
    /// If there is an [`IPv4`](crate::ipv4::Ipv4) or [`IPv6`](crate::ipv6::Ipv6) layer present,
    /// the length of that header will be updated accordingly.
    ///
    /// # Errors
    /// Returns an error if:
    /// - the provided `length` is smaller than eight.
    /// - the `length` exceeds the available space.
    #[inline]
    fn set_udp_length(&mut self, length: u16) -> Result<(), SetLengthError> {
        let length_usize = usize::from(length);

        if length_usize < HEADER_MIN_LEN {
            return Err(SetLengthError::LengthTooSmall {
                length: length_usize,
            });
        }

        let data_length = self.header_start_offset(LAYER) + length_usize;
        self.set_data_length(data_length, self.buffer_length())?;

        self.write_slice(LAYER, LENGTH, &length.to_be_bytes());
        self.update_ip_length();
        Ok(())
    }

    /// Sets the UDP checksum.
    #[inline]
    fn set_udp_checksum(&mut self, checksum: u16) {
        self.write_slice(LAYER, CHECKSUM, &checksum.to_be_bytes());
    }

    /// Calculates and updates the UDP checksum.
    ///
    /// This takes lower layers into account.
    /// If there is an [`IPv4`](crate::ipv4::Ipv4) or [`IPv6`](crate::ipv6::Ipv6) layer present,
    /// the pseudo header will be included.
    /// If there is a [`NoPreviousHeader`](crate::no_previous_header::NoPreviousHeader) present,
    /// the pseudo header is set to zero.
    #[inline]
    fn update_udp_checksum(&mut self) {
        self.write_slice(LAYER, CHECKSUM, &[0, 0]);
        let checksum = self.udp_calculate_checksum();
        self.write_slice(LAYER, CHECKSUM, &checksum.to_be_bytes());
    }
}
