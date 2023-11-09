//! IPv4 access and manipulation methods.

use crate::addresses::ipv4::Ipv4Address;
use crate::checksum::internet_checksum_up_to_64_bytes;
use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderManipulation, HeaderMetadata, Layer,
};
use crate::internal_utils::grow_or_shrink_header_at_end;
use crate::ipv4::{SetIhlError, SetTotalLengthError};
use crate::typed_protocol_headers::{Dscp, Ecn, UnrecognizedDscpError, UnrecognizedEcnError};
use crate::typed_protocol_headers::{
    InternetProtocolNumber, UnrecognizedInternetProtocolNumberError,
};
use core::ops::Range;
use core::ops::RangeInclusive;

pub(crate) const VERSION_BYTE: usize = 0;
pub(crate) const VERSION_SHIFT: usize = 4;
pub(crate) const IHL_BYTE: usize = 0;
pub(crate) const IHL_MASK: u8 = 0b0000_1111;
pub(crate) const DSCP_BYTE: usize = 1;
pub(crate) const DSCP_MASK: u8 = 0b1111_1100;
pub(crate) const DSCP_SHIFT: usize = 2;
pub(crate) const ECN_BYTE: usize = 1;
pub(crate) const ECN_MASK: u8 = 0b0000_0011;
pub(crate) const TOTAL_LENGTH: Range<usize> = 2..4;
pub(crate) const IDENTIFICATION: Range<usize> = 4..6;
pub(crate) const FLAGS_BYTE: usize = 6;
pub(crate) const FLAGS_MASK: u8 = 0b1110_0000;
pub(crate) const FLAGS_SHIFT: usize = 5;
pub(crate) const FLAGS_EVIL_MASK: u8 = 0b1000_0000;
pub(crate) const FLAGS_EVIL_SHIFT: usize = 7;
pub(crate) const FLAGS_DONT_FRAGMENT_MASK: u8 = 0b0100_0000;
pub(crate) const FLAGS_DONT_FRAGMENT_SHIFT: usize = 6;
pub(crate) const FLAGS_MORE_FRAGMENTS_MASK: u8 = 0b0010_0000;
pub(crate) const FLAGS_MORE_FRAGMENTS_SHIFT: usize = 5;
pub(crate) const FRAGMENT_OFFSET_MASK: u16 = 0b0001_1111_1111_1111;
pub(crate) const FRAGMENT_OFFSET_FLAG_SHIFT: usize = 13;
pub(crate) const FRAGMENT_OFFSET: Range<usize> = 6..8;
pub(crate) const TIME_TO_LIVE: usize = 8;
pub(crate) const PROTOCOL: usize = 9;
pub(crate) const CHECKSUM: Range<usize> = 10..12;
pub(crate) const SOURCE: Range<usize> = 12..16;
pub(crate) const DESTINATION: Range<usize> = 16..20;
pub(crate) const OPTIONS_START: usize = 20;

pub(crate) const HEADER_MIN_LEN: usize = 20;

pub(crate) const IHL_RANGE: RangeInclusive<usize> = 5..=15;

pub(crate) const LAYER: Layer = Layer::Ipv4;

// Length manipulating methods:
// - set_ipv4_total_length (has proof)
// - set_ipv4_ihl (has proof)

/// Methods available for [`DataBuffer`](crate::data_buffer::DataBuffer) containing an
/// [`Ipv4`](crate::ipv4::Ipv4) header.
pub trait Ipv4Methods: HeaderMetadata + BufferAccess {
    /// Returns the IPv4 version.
    #[inline]
    fn ipv4_version(&self) -> u8 {
        self.read_value(LAYER, VERSION_BYTE) >> VERSION_SHIFT
    }

    /// Returns the IPv4 IHL.
    #[inline]
    fn ipv4_ihl(&self) -> u8 {
        self.read_value(LAYER, IHL_BYTE) & IHL_MASK
    }

    /// Returns the IPv4 DSCP.
    #[inline]
    fn ipv4_dscp(&self) -> u8 {
        self.read_value(LAYER, DSCP_BYTE) >> DSCP_SHIFT
    }

    /// Returns the IPv4 DSCP as [`Dscp`]
    ///
    /// # Errors
    ///
    /// Returns an error if the DSCP is not recognized.
    #[inline]
    fn ipv4_typed_dscp(&self) -> Result<Dscp, UnrecognizedDscpError> {
        self.ipv4_dscp().try_into()
    }

    /// Returns the IPv4 ECN.
    #[inline]
    fn ipv4_ecn(&self) -> u8 {
        self.read_value(LAYER, ECN_BYTE) & ECN_MASK
    }

    /// Returns the IPv4 ECN as [`Ecn`]
    ///
    /// # Errors
    ///
    /// Returns an error if the ECN is not recognized.
    #[inline]
    fn ipv4_typed_ecn(&self) -> Result<Ecn, UnrecognizedEcnError> {
        self.ipv4_ecn().try_into()
    }

    /// Returns the IPv4 total length.
    #[inline]
    fn ipv4_total_length(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, TOTAL_LENGTH))
    }

    /// Returns the IPv4 identification.
    #[inline]
    fn ipv4_identification(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, IDENTIFICATION))
    }

    /// Returns the IPv4 flags.
    #[inline]
    fn ipv4_flags(&self) -> u8 {
        self.read_value(LAYER, FLAGS_BYTE) >> FLAGS_SHIFT
    }

    /// Returns the IPv4 evil flag.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc3514>
    #[inline]
    fn ipv4_evil_flag(&self) -> bool {
        (self.read_value(LAYER, FLAGS_BYTE) & FLAGS_EVIL_MASK) != 0
    }

    /// Returns the IPv4 don't fragment flag.
    #[inline]
    fn ipv4_dont_fragment_flag(&self) -> bool {
        (self.read_value(LAYER, FLAGS_BYTE) & FLAGS_DONT_FRAGMENT_MASK) != 0
    }

    /// Returns the IPv4 more fragments flag.
    #[inline]
    fn ipv4_more_fragments_flag(&self) -> bool {
        (self.read_value(LAYER, FLAGS_BYTE) & FLAGS_MORE_FRAGMENTS_MASK) != 0
    }

    /// Returns the IPv4 fragment offset.
    #[inline]
    fn ipv4_fragment_offset(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, FRAGMENT_OFFSET)) & FRAGMENT_OFFSET_MASK
    }

    /// Returns the IPv4 time to live.
    #[inline]
    fn ipv4_time_to_live(&self) -> u8 {
        self.read_value(LAYER, TIME_TO_LIVE)
    }

    /// Returns the IPv4 protocol.
    #[inline]
    fn ipv4_protocol(&self) -> u8 {
        self.read_value(LAYER, PROTOCOL)
    }

    /// Returns the IPv4 protocol as [`InternetProtocolNumber`]
    ///
    /// # Errors
    ///
    /// Returns an error if the protocol is not recognized.
    #[inline]
    fn ipv4_typed_protocol(
        &self,
    ) -> Result<InternetProtocolNumber, UnrecognizedInternetProtocolNumberError> {
        self.ipv4_protocol().try_into()
    }

    /// Returns the IPv4 header checksum.
    #[inline]
    fn ipv4_header_checksum(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, CHECKSUM))
    }

    /// Calculates and returns the IPv4 header checksum.
    ///
    /// This does take the current checksum field into account.
    /// To calculate the checksum and set it, use [`Ipv4MethodsMut::update_ipv4_header_checksum`].
    #[inline]
    fn ipv4_calculate_checksum(&self) -> u16 {
        internet_checksum_up_to_64_bytes(self.read_slice(LAYER, 0..self.header_length(LAYER)))
    }

    /// Returns the IPv4 source.
    #[inline]
    fn ipv4_source(&self) -> Ipv4Address {
        self.read_array(LAYER, SOURCE)
    }

    /// Returns the IPv4 destination.
    #[inline]
    fn ipv4_destination(&self) -> Ipv4Address {
        self.read_array(LAYER, DESTINATION)
    }

    /// Returns a slice containing the IPv4 options.
    ///
    /// Returns an empty slice if no options are present.
    #[inline]
    fn ipv4_options(&self) -> &[u8] {
        let ihl_header = usize::from(self.ipv4_ihl()).saturating_sub(5);

        self.read_slice(LAYER, OPTIONS_START..OPTIONS_START + ihl_header * 4)
    }

    /// Returns the IPv4 payload length.
    #[inline]
    fn ipv4_payload_length(&self) -> u16 {
        self.ipv4_total_length() - (u16::from(self.ipv4_ihl()) * 4)
    }
}

/// Methods available for [`DataBuffer`](crate::data_buffer::DataBuffer) containing an
/// [`Ipv4`](crate::ipv4::Ipv4) header and wrapping a mutable data buffer.
pub trait Ipv4MethodsMut:
    Ipv4Methods + BufferAccessMut + HeaderManipulation + UpdateIpv4Length + Sized
{
    /// Sets the IPv4 IHL.
    ///
    /// Updates the IPv4 total length header.
    ///
    /// # Errors
    /// Returns an error if:
    /// - `ihl` is not within the valid bounds (5..=15).
    /// - there is not enough headroom available to accommodate the size change.
    #[inline]
    fn set_ipv4_ihl(&mut self, ihl: u8) -> Result<(), SetIhlError> {
        let new_ihl_usize = usize::from(ihl);
        if !IHL_RANGE.contains(&new_ihl_usize) {
            return Err(SetIhlError::InvalidIhl { ihl: new_ihl_usize });
        }
        let current_ihl_in_bytes = usize::from(self.ipv4_ihl()) * 4;
        let new_ihl_in_bytes = new_ihl_usize * 4;
        grow_or_shrink_header_at_end(self, current_ihl_in_bytes, new_ihl_in_bytes, LAYER)?;

        let new_ihl_byte = (self.read_value(LAYER, IHL_BYTE) & !IHL_MASK) | ihl;
        self.write_value(LAYER, IHL_BYTE, new_ihl_byte);
        self.update_ipv4_length();
        Ok(())
    }

    /// Sets the IPv4 DSCP.
    #[inline]
    fn set_ipv4_dscp(&mut self, dscp: Dscp) {
        let mut dscp = (dscp as u8) << DSCP_SHIFT;
        dscp |= self.read_value(LAYER, DSCP_BYTE) & !DSCP_MASK;
        self.write_value(LAYER, DSCP_BYTE, dscp);
    }

    /// Sets the IPv4 ECN.
    #[inline]
    fn set_ipv4_ecn(&mut self, ecn: Ecn) {
        let mut ecn = ecn as u8 & ECN_MASK;
        ecn |= self.read_value(LAYER, ECN_BYTE) & !ECN_MASK;
        self.write_value(LAYER, ECN_BYTE, ecn);
    }

    /// Sets the IPv4 total length.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `total_length` is less than the current IHL.
    /// - `total_length` exceeds the available space.
    /// - the length of `total_length` would cause already parsed upper layers to be cut of.
    #[inline]
    fn set_ipv4_total_length(&mut self, total_length: u16) -> Result<(), SetTotalLengthError> {
        let total_length_usize = usize::from(total_length);
        let ipv4_header_length_in_bytes = usize::from(self.ipv4_ihl()) * 4;
        if total_length_usize < ipv4_header_length_in_bytes {
            return Err(SetTotalLengthError::SmallerThanIhl);
        }
        // Don't allow cutting already parsed upper layers
        if self.layer() != LAYER {
            let ipv4_and_intermediate_upper_headers_length =
                self.header_start_offset(self.layer()) - self.header_start_offset(LAYER);
            let highest_headers_length = self.header_length(self.layer());
            if total_length_usize
                < ipv4_and_intermediate_upper_headers_length + highest_headers_length
            {
                return Err(SetTotalLengthError::CannotCutUpperLayerHeader);
            }
        }

        let data_length = self.header_start_offset(LAYER) + total_length_usize;
        self.set_data_length(data_length, self.buffer_length())?;
        self.write_slice(LAYER, TOTAL_LENGTH, &total_length.to_be_bytes());
        Ok(())
    }

    /// Sets the IPv4 identification.
    #[inline]
    fn set_ipv4_identification(&mut self, identification: u16) {
        self.write_slice(LAYER, IDENTIFICATION, &identification.to_be_bytes());
    }

    /// Sets the IPv4 flags.
    #[inline]
    fn set_ipv4_flags(&mut self, mut flags: u8) {
        flags <<= FLAGS_SHIFT;
        flags |= self.read_value(LAYER, FLAGS_BYTE) & !FLAGS_MASK;
        self.write_value(LAYER, FLAGS_BYTE, flags);
    }

    /// Sets the IPv4 evil flag.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc3514>
    #[inline]
    fn set_ipv4_evil_flag(&mut self, evil: bool) {
        let evil_flag = (self.read_value(LAYER, FLAGS_BYTE) & !FLAGS_EVIL_MASK)
            | u8::from(evil) << FLAGS_EVIL_SHIFT;
        self.write_value(LAYER, FLAGS_BYTE, evil_flag);
    }

    /// Sets the IPv4 don't fragment flag.
    #[inline]
    fn set_ipv4_dont_fragment_flag(&mut self, dont_fragment: bool) {
        let dont_fragment_flag = (self.read_value(LAYER, FLAGS_BYTE) & !FLAGS_DONT_FRAGMENT_MASK)
            | u8::from(dont_fragment) << FLAGS_DONT_FRAGMENT_SHIFT;
        self.write_value(LAYER, FLAGS_BYTE, dont_fragment_flag);
    }

    /// Sets the IPv4 more fragments flag.
    #[inline]
    fn set_ipv4_more_fragments_flag(&mut self, more_fragments: bool) {
        let more_fragments_flags = (self.read_value(LAYER, FLAGS_BYTE)
            & !FLAGS_MORE_FRAGMENTS_MASK)
            | u8::from(more_fragments) << FLAGS_MORE_FRAGMENTS_SHIFT;
        self.write_value(LAYER, FLAGS_BYTE, more_fragments_flags);
    }

    /// Sets the IPv4 fragment offset.
    #[inline]
    fn set_ipv4_fragment_offset(&mut self, mut fragment_offset: u16) {
        fragment_offset &= FRAGMENT_OFFSET_MASK;
        fragment_offset &=
            (u16::from(self.ipv4_flags()) << FRAGMENT_OFFSET_FLAG_SHIFT) | FRAGMENT_OFFSET_MASK;
        self.write_slice(
            LAYER,
            FRAGMENT_OFFSET,
            fragment_offset.to_be_bytes().as_slice(),
        );
    }

    /// Sets the IPv4 time to live.
    #[inline]
    fn set_ipv4_time_to_live(&mut self, time_to_live: u8) {
        self.write_value(LAYER, TIME_TO_LIVE, time_to_live);
    }

    /// Sets the IPv4 protocol.
    #[inline]
    fn set_ipv4_protocol(&mut self, protocol: u8) {
        self.write_value(LAYER, PROTOCOL, protocol);
    }

    /// Sets the IPv4 header checksum.
    #[inline]
    fn set_ipv4_header_checksum(&mut self, checksum: u16) {
        self.write_slice(LAYER, CHECKSUM, &checksum.to_be_bytes());
    }

    /// Calculates and updates the IPv4 checksum.
    #[inline]
    fn update_ipv4_header_checksum(&mut self) {
        self.write_slice(LAYER, CHECKSUM, &[0, 0]);
        let checksum = self.ipv4_calculate_checksum();
        self.write_slice(LAYER, CHECKSUM, &checksum.to_be_bytes());
    }

    /// Sets the IPv4 source.
    #[inline]
    fn set_ipv4_source(&mut self, source: Ipv4Address) {
        self.write_slice(LAYER, SOURCE, &source);
    }

    /// Sets the IPv4 destination.
    #[inline]
    fn set_ipv4_destination(&mut self, destination: Ipv4Address) {
        self.write_slice(LAYER, DESTINATION, &destination);
    }

    /// Returns a mutable slice containing the IPv4 options.
    ///
    /// Returns an empty slice if there are no options present.
    #[inline]
    fn ipv4_options_mut(&mut self) -> &mut [u8] {
        let ihl_header = usize::from(self.ipv4_ihl()).saturating_sub(5);

        self.get_slice_mut(LAYER, OPTIONS_START..OPTIONS_START + ihl_header * 4)
    }
}

/// Allows updating the IPv4 length from other layers.
pub(crate) trait UpdateIpv4Length:
    HeaderManipulation + BufferAccessMut + Ipv4Methods + Sized
{
    #[inline]
    fn update_ipv4_length(&mut self) {
        let ipv4_length = self.data_length() - self.header_start_offset(LAYER);

        self.write_slice(LAYER, TOTAL_LENGTH, &(ipv4_length as u16).to_be_bytes());
    }
}
