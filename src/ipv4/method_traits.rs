use crate::addresses::ipv4::Ipv4Address;
use crate::checksum::internet_checksum_up_to_64_bytes;
use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderInformation, HeaderManipulation, Layer,
};
use crate::internal_utils::grow_or_shrink_header_at_end;
use crate::internet_protocol::{InternetProtocolNumber, NoRecognizedInternetProtocolNumberError};
use crate::ipv4::{
    Dscp, Ecn, NoRecognizedDscpError, NoRecognizedEcnError, SetIhlError, SetTotalLengthError,
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

pub trait Ipv4Methods: HeaderInformation + BufferAccess {
    #[inline]
    fn ipv4_version(&self) -> u8 {
        self.data_buffer_starting_at_header(LAYER)[VERSION_BYTE] >> VERSION_SHIFT
    }

    #[inline]
    fn ipv4_ihl(&self) -> u8 {
        self.data_buffer_starting_at_header(LAYER)[IHL_BYTE] & IHL_MASK
    }

    #[inline]
    fn ipv4_dscp(&self) -> u8 {
        self.data_buffer_starting_at_header(LAYER)[DSCP_BYTE] >> DSCP_SHIFT
    }

    #[inline]
    fn ipv4_typed_dscp(&self) -> Result<Dscp, NoRecognizedDscpError> {
        (self.data_buffer_starting_at_header(LAYER)[DSCP_BYTE] >> 2).try_into()
    }

    #[inline]
    fn ipv4_ecn(&self) -> u8 {
        self.data_buffer_starting_at_header(LAYER)[ECN_BYTE] & ECN_MASK
    }

    #[inline]
    fn ipv4_typed_ecn(&self) -> Result<Ecn, NoRecognizedEcnError> {
        (self.data_buffer_starting_at_header(LAYER)[ECN_BYTE] & ECN_MASK).try_into()
    }

    #[inline]
    fn ipv4_total_length(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[TOTAL_LENGTH]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn ipv4_identification(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[IDENTIFICATION]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn ipv4_flags(&self) -> u8 {
        self.data_buffer_starting_at_header(LAYER)[FLAGS_BYTE] >> FLAGS_SHIFT
    }

    /// <https://datatracker.ietf.org/doc/html/rfc3514>
    #[inline]
    fn ipv4_evil_flag(&self) -> bool {
        (self.data_buffer_starting_at_header(LAYER)[FLAGS_BYTE] & FLAGS_EVIL_MASK) != 0
    }

    #[inline]
    fn ipv4_dont_fragment_flag(&self) -> bool {
        (self.data_buffer_starting_at_header(LAYER)[FLAGS_BYTE] & FLAGS_DONT_FRAGMENT_MASK) != 0
    }

    #[inline]
    fn ipv4_more_fragments_flag(&self) -> bool {
        (self.data_buffer_starting_at_header(LAYER)[FLAGS_BYTE] & FLAGS_MORE_FRAGMENTS_MASK) != 0
    }

    #[inline]
    fn ipv4_fragment_offset(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[FRAGMENT_OFFSET]
                .try_into()
                .unwrap(),
        ) & FRAGMENT_OFFSET_MASK
    }

    #[inline]
    fn ipv4_time_to_live(&self) -> u8 {
        self.data_buffer_starting_at_header(LAYER)[TIME_TO_LIVE]
    }

    #[inline]
    fn ipv4_protocol(&self) -> u8 {
        self.data_buffer_starting_at_header(LAYER)[PROTOCOL]
    }

    #[inline]
    fn ipv4_typed_protocol(
        &self,
    ) -> Result<InternetProtocolNumber, NoRecognizedInternetProtocolNumberError> {
        self.data_buffer_starting_at_header(LAYER)[PROTOCOL].try_into()
    }

    #[inline]
    fn ipv4_header_checksum(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[CHECKSUM]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn ipv4_calculate_checksum(&self) -> u16 {
        internet_checksum_up_to_64_bytes(
            &self.data_buffer_starting_at_header(LAYER)[0..self.header_length(LAYER)],
        )
    }

    #[inline]
    fn ipv4_source(&self) -> Ipv4Address {
        self.data_buffer_starting_at_header(LAYER)[SOURCE]
            .try_into()
            .unwrap()
    }

    #[inline]
    fn ipv4_destination(&self) -> Ipv4Address {
        self.data_buffer_starting_at_header(LAYER)[DESTINATION]
            .try_into()
            .unwrap()
    }

    #[inline]
    fn ipv4_options(&self) -> Option<&[u8]> {
        let ihl_header = usize::from(self.ipv4_ihl());
        if ihl_header <= *IHL_RANGE.start() {
            None
        } else {
            Some(&self.data_buffer_starting_at_header(LAYER)[OPTIONS_START..ihl_header * 4])
        }
    }

    #[inline]
    fn ipv4_payload_length(&self) -> u16 {
        self.ipv4_total_length() - (u16::from(self.ipv4_ihl()) * 4)
    }
}

pub trait Ipv4MethodsMut:
    Ipv4Methods + BufferAccessMut + HeaderManipulation + UpdateIpv4Length + Sized
{
    #[inline]
    fn set_ipv4_ihl(&mut self, ihl: u8) -> Result<(), SetIhlError> {
        let new_ihl_usize = usize::from(ihl);
        if !IHL_RANGE.contains(&new_ihl_usize) {
            return Err(SetIhlError::InvalidIhl { ihl: new_ihl_usize });
        }
        let current_ihl_in_bytes = usize::from(self.ipv4_ihl()) * 4;
        let new_ihl_in_bytes = new_ihl_usize * 4;
        grow_or_shrink_header_at_end(self, current_ihl_in_bytes, new_ihl_in_bytes, LAYER)?;

        let new_ihl_byte = (self.data_buffer_starting_at_header(LAYER)[IHL_BYTE] & !IHL_MASK) | ihl;
        self.data_buffer_starting_at_header_mut(LAYER)[IHL_BYTE] = new_ihl_byte;
        self.update_ipv4_length();
        Ok(())
    }

    #[inline]
    fn set_ipv4_dscp(&mut self, dscp: Dscp) {
        let dscp = (dscp as u8) << DSCP_SHIFT;
        self.data_buffer_starting_at_header_mut(LAYER)[DSCP_BYTE] =
            (self.data_buffer_starting_at_header_mut(LAYER)[DSCP_BYTE] & !DSCP_MASK) | dscp;
    }

    #[inline]
    fn set_ipv4_ecn(&mut self, ecn: Ecn) {
        let ecn = ecn as u8 & ECN_MASK;
        self.data_buffer_starting_at_header_mut(LAYER)[ECN_BYTE] =
            (self.data_buffer_starting_at_header_mut(LAYER)[ECN_BYTE] & !ECN_MASK) | ecn;
    }

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
        self.data_buffer_starting_at_header_mut(LAYER)[TOTAL_LENGTH]
            .copy_from_slice(&total_length.to_be_bytes());
        Ok(())
    }

    #[inline]
    fn set_ipv4_identification(&mut self, identification: u16) {
        self.data_buffer_starting_at_header_mut(LAYER)[IDENTIFICATION]
            .copy_from_slice(&identification.to_be_bytes())
    }

    #[inline]
    fn set_ipv4_flags(&mut self, flags: u8) {
        let flags = flags << FLAGS_SHIFT;
        self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] =
            (self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] & !FLAGS_MASK) | flags;
    }

    /// <https://datatracker.ietf.org/doc/html/rfc3514>
    #[inline]
    fn set_ipv4_evil_flag(&mut self, evil: bool) {
        self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] =
            (self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] & !FLAGS_EVIL_MASK)
                | (evil as u8) << FLAGS_EVIL_SHIFT;
    }

    #[inline]
    fn set_ipv4_dont_fragment_flag(&mut self, dont_fragment: bool) {
        self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] = (self
            .data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE]
            & !FLAGS_DONT_FRAGMENT_MASK)
            | (dont_fragment as u8) << FLAGS_DONT_FRAGMENT_SHIFT;
    }

    #[inline]
    fn set_ipv4_more_fragments_flag(&mut self, more_fragments: bool) {
        self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] = (self
            .data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE]
            & !FLAGS_MORE_FRAGMENTS_MASK)
            | (more_fragments as u8) << FLAGS_MORE_FRAGMENTS_SHIFT;
    }

    #[inline]
    fn set_ipv4_fragment_offset(&mut self, fragment_offset: u16) {
        let mut fragment_offset = fragment_offset & FRAGMENT_OFFSET_MASK;
        fragment_offset &=
            (u16::from(self.ipv4_flags()) << FRAGMENT_OFFSET_FLAG_SHIFT) | FRAGMENT_OFFSET_MASK;
        self.data_buffer_starting_at_header_mut(LAYER)[FRAGMENT_OFFSET]
            .copy_from_slice(fragment_offset.to_be_bytes().as_slice());
    }

    #[inline]
    fn set_ipv4_time_to_live(&mut self, time_to_live: u8) {
        self.data_buffer_starting_at_header_mut(LAYER)[TIME_TO_LIVE] = time_to_live
    }

    #[inline]
    fn set_ipv4_protocol(&mut self, protocol: u8) {
        self.data_buffer_starting_at_header_mut(LAYER)[PROTOCOL] = protocol;
    }

    #[inline]
    fn set_ipv4_header_checksum(&mut self, checksum: u16) {
        self.data_buffer_starting_at_header_mut(LAYER)[CHECKSUM]
            .copy_from_slice(&checksum.to_be_bytes());
    }

    #[inline]
    fn update_ipv4_header_checksum(&mut self) {
        self.data_buffer_starting_at_header_mut(LAYER)[CHECKSUM].copy_from_slice(&[0, 0]);
        let checksum = self.ipv4_calculate_checksum();
        self.data_buffer_starting_at_header_mut(LAYER)[CHECKSUM]
            .copy_from_slice(&checksum.to_be_bytes());
    }

    #[inline]
    fn set_ipv4_source(&mut self, source: Ipv4Address) {
        self.data_buffer_starting_at_header_mut(LAYER)[SOURCE].copy_from_slice(&source)
    }

    #[inline]
    fn set_ipv4_destination(&mut self, destination: Ipv4Address) {
        self.data_buffer_starting_at_header_mut(LAYER)[DESTINATION].copy_from_slice(&destination)
    }

    #[inline]
    fn ipv4_options_mut(&mut self) -> Option<&mut [u8]> {
        let ihl_header = usize::from(self.ipv4_ihl());
        assert!(ihl_header >= *IHL_RANGE.start());

        let ihl_in_bytes = ihl_header * 4;
        Some(&mut self.data_buffer_starting_at_header_mut(LAYER)[OPTIONS_START..ihl_in_bytes])
    }
}

pub(crate) trait UpdateIpv4Length:
    HeaderManipulation + BufferAccessMut + Ipv4Methods + Sized
{
    #[inline]
    fn update_ipv4_length(&mut self) {
        let ipv4_length = self.data_length() - self.header_start_offset(LAYER);

        self.data_buffer_starting_at_header_mut(LAYER)[TOTAL_LENGTH]
            .copy_from_slice(&(ipv4_length as u16).to_be_bytes());
    }
}
