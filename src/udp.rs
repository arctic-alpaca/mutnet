//! UDP type and method traits.

mod error;
mod method_traits;

#[cfg(all(feature = "remove_checksum", feature = "verify_udp", kani))]
mod verification;

use crate::constants::UDP;
use crate::data_buffer::traits::HeaderInformationExtraction;
use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderInformation, HeaderInformationMut, Layer,
};
use crate::data_buffer::{
    BufferIntoInner, DataBuffer, EthernetMarker, Ieee802_1QVlanMarker, Ipv4Marker, Ipv6ExtMarker,
    Ipv6Marker, Payload, PayloadMut, UdpMarker,
};
use crate::error::{UnexpectedBufferEndError, WrongChecksumError};
use crate::internal_utils::{
    check_and_calculate_data_length, header_start_offset_from_phi,
    pseudoheader_checksum_ipv4_internal, pseudoheader_checksum_ipv6_internal,
};
use crate::ipv4::{Ipv4, Ipv4Methods, UpdateIpv4Length};
use crate::ipv6::{Ipv6, UpdateIpv6Length};
use crate::ipv6_extensions::{Ipv6ExtMetaData, Ipv6ExtMetaDataMut, Ipv6Extensions};
use crate::ipv6_extensions::{Ipv6ExtensionIndexOutOfBoundsError, Ipv6ExtensionMetadata};
use crate::no_previous_header::NoPreviousHeaderInformation;
use crate::utility_traits::{TcpUdpChecksum, UpdateIpLength};
pub use error::*;
pub use method_traits::*;

/// UDP metadata.
///
/// Contains meta data about the UDP header in the parsed data buffer.
#[derive(Eq, PartialEq, Hash, Copy, Clone, Debug)]
pub struct Udp<PHI>
where
    PHI: HeaderInformation + HeaderInformationMut,
{
    header_start_offset: usize,
    header_length: usize,
    previous_header_information: PHI,
}

impl<PHI> EthernetMarker for Udp<PHI> where
    PHI: HeaderInformation + HeaderInformationMut + EthernetMarker
{
}
impl<PHI> Ieee802_1QVlanMarker for Udp<PHI> where
    PHI: HeaderInformation + HeaderInformationMut + Ieee802_1QVlanMarker
{
}
impl<PHI> Ipv4Marker for Udp<PHI> where PHI: HeaderInformation + HeaderInformationMut + Ipv4Marker {}
impl<PHI> Ipv6Marker for Udp<PHI> where PHI: HeaderInformation + HeaderInformationMut + Ipv6Marker {}
impl<PHI, const MAX_EXTENSIONS: usize> Ipv6ExtMarker<MAX_EXTENSIONS> for Udp<PHI> where
    PHI: HeaderInformation + HeaderInformationMut + Ipv6ExtMarker<MAX_EXTENSIONS>
{
}
impl<PHI> UdpMarker for Udp<PHI> where PHI: HeaderInformation + HeaderInformationMut {}

impl<B, PHI> DataBuffer<B, Udp<PHI>>
where
    B: AsRef<[u8]>,
    PHI: HeaderInformation + HeaderInformationMut + Copy,
    DataBuffer<B, Udp<PHI>>: TcpUdpChecksum,
{
    /// Parses `buf` and creates a new [DataBuffer] for an UDP layer with no previous layers.
    ///
    /// `headroom` indicates the amount of headroom in the provided `buf`.
    /// No checksum can be calculated without underlying header for the pseudo header.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided data buffer is shorter than expected.
    /// - the length field value is invalid.
    #[inline]
    pub fn new_without_checksum(
        buf: B,
        headroom: usize,
    ) -> Result<DataBuffer<B, Udp<NoPreviousHeaderInformation>>, ParseUdpError> {
        let lower_layer_data_buffer =
            DataBuffer::<B, NoPreviousHeaderInformation>::new(buf, headroom)?;

        DataBuffer::<B, Udp<NoPreviousHeaderInformation>>::new_from_lower(
            lower_layer_data_buffer,
            false,
        )
    }

    /// Consumes the `lower_layer_data_buffer` and creates a new [DataBuffer] with an additional
    /// UDP layer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided data buffer is shorter than expected.
    /// - the length field value is invalid.
    /// - if `check_udp_checksum` is true and the checksum is invalid.
    #[inline]
    pub fn new_from_lower(
        lower_layer_data_buffer: impl HeaderInformation
            + Payload
            + BufferIntoInner<B>
            + HeaderInformationExtraction<PHI>,
        check_udp_checksum: bool,
    ) -> Result<DataBuffer<B, Udp<PHI>>, ParseUdpError> {
        let previous_header_information = lower_layer_data_buffer.extract_header_information();

        let data_length = check_and_calculate_data_length::<ParseUdpError>(
            lower_layer_data_buffer.payload_length(),
            0,
            HEADER_MIN_LEN,
        )?;

        let length_header = usize::from(u16::from_be_bytes(
            lower_layer_data_buffer.payload()[LENGTH_START..LENGTH_END]
                .try_into()
                .unwrap(),
        ));

        if length_header < HEADER_MIN_LEN {
            return Err(ParseUdpError::LengthHeaderTooSmall { length_header });
        }

        if length_header > data_length {
            return Err(ParseUdpError::LengthHeaderTooLarge {
                expected: data_length,
                actual: length_header,
            });
        }

        let result = DataBuffer {
            header_information: Udp {
                header_start_offset: header_start_offset_from_phi(previous_header_information),
                header_length: HEADER_MIN_LEN,
                previous_header_information: *previous_header_information,
            },
            buffer: lower_layer_data_buffer.buffer_into_inner(),
        };

        if check_udp_checksum {
            let checksum = result.udp_calculate_checksum();
            if checksum != 0 {
                return Err(ParseUdpError::WrongChecksum(WrongChecksumError {
                    calculated_checksum: checksum,
                }));
            }
        }

        Ok(result)
    }
}

impl<B> TcpUdpChecksum for DataBuffer<B, Udp<NoPreviousHeaderInformation>>
where
    B: AsRef<[u8]>,
{
    #[inline]
    fn pseudoheader_checksum(&self, _tcp_udp_length: usize) -> u64 {
        0
    }
}

impl<B> UpdateIpLength for DataBuffer<B, Udp<NoPreviousHeaderInformation>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    fn update_ip_length(&mut self) {}
}

impl<B, PHI> UpdateIpLength for DataBuffer<B, Udp<Ipv4<PHI>>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    PHI: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn update_ip_length(&mut self) {
        self.update_ipv4_length()
    }
}

impl<B, PHI> UpdateIpLength for DataBuffer<B, Udp<Ipv6<PHI>>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    PHI: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn update_ip_length(&mut self) {
        self.update_ipv6_length()
    }
}

impl<B, PHI, const MAX_EXTENSIONS: usize> UpdateIpLength
    for DataBuffer<B, Udp<Ipv6Extensions<PHI, MAX_EXTENSIONS>>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    PHI: HeaderInformation + HeaderInformationMut + Ipv6Marker,
{
    #[inline]
    fn update_ip_length(&mut self) {
        self.update_ipv6_length()
    }
}

impl<B, PHI> TcpUdpChecksum for DataBuffer<B, Udp<Ipv4<PHI>>>
where
    B: AsRef<[u8]>,
    PHI: HeaderInformation + HeaderInformationMut,
    DataBuffer<B, Udp<Ipv4<PHI>>>: Ipv4Methods,
{
    #[inline]
    fn pseudoheader_checksum(&self, tcp_udp_length: usize) -> u64 {
        pseudoheader_checksum_ipv4_internal(self, tcp_udp_length, UDP)
    }
}

impl<B, PHI> TcpUdpChecksum for DataBuffer<B, Udp<Ipv6<PHI>>>
where
    B: AsRef<[u8]>,
    PHI: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn pseudoheader_checksum(&self, tcp_udp_length: usize) -> u64 {
        pseudoheader_checksum_ipv6_internal(self, tcp_udp_length, UDP)
    }
}

impl<B, PHI, const MAX_EXTENSIONS: usize> TcpUdpChecksum
    for DataBuffer<B, Udp<Ipv6Extensions<PHI, MAX_EXTENSIONS>>>
where
    B: AsRef<[u8]>,
    PHI: HeaderInformation + HeaderInformationMut + Ipv6Marker,
{
    #[inline]
    fn pseudoheader_checksum(&self, tcp_udp_length: usize) -> u64 {
        pseudoheader_checksum_ipv6_internal(self, tcp_udp_length, UDP)
    }
}

impl<PHI> HeaderInformation for Udp<PHI>
where
    PHI: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn headroom(&self) -> usize {
        self.previous_header_information.headroom()
    }

    #[inline]
    fn header_start_offset(&self, layer: Layer) -> usize {
        if layer == LAYER {
            self.header_start_offset
        } else {
            self.previous_header_information.header_start_offset(layer)
        }
    }

    #[inline]
    fn header_length(&self, layer: Layer) -> usize {
        if layer == LAYER {
            self.header_length
        } else {
            self.previous_header_information.header_length(layer)
        }
    }

    #[inline]
    fn layer(&self) -> Layer {
        LAYER
    }

    #[inline]
    fn data_length(&self) -> usize {
        self.previous_header_information.data_length()
    }
}

impl<PHI, const MAX_EXTENSIONS: usize> Ipv6ExtMetaData<MAX_EXTENSIONS> for Udp<PHI>
where
    PHI: HeaderInformation + HeaderInformationMut + Ipv6ExtMarker<MAX_EXTENSIONS>,
{
    #[inline]
    fn extensions(&self) -> &[Ipv6ExtensionMetadata; MAX_EXTENSIONS] {
        self.previous_header_information.extensions()
    }

    #[inline]
    fn extension(
        &self,
        idx: usize,
    ) -> Result<Ipv6ExtensionMetadata, Ipv6ExtensionIndexOutOfBoundsError> {
        self.previous_header_information.extension(idx)
    }

    #[inline]
    fn extensions_amount(&self) -> usize {
        self.previous_header_information.extensions_amount()
    }
}

impl<PHI, const MAX_EXTENSIONS: usize> Ipv6ExtMetaDataMut<MAX_EXTENSIONS> for Udp<PHI>
where
    PHI: HeaderInformation + HeaderInformationMut + Ipv6ExtMarker<MAX_EXTENSIONS>,
{
    #[inline]
    fn extensions_mut(&mut self) -> &mut [Ipv6ExtensionMetadata; MAX_EXTENSIONS] {
        self.previous_header_information.extensions_mut()
    }
}

impl<PHI> HeaderInformationMut for Udp<PHI>
where
    PHI: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn headroom_mut(&mut self) -> &mut usize {
        self.previous_header_information.headroom_mut()
    }

    #[inline]
    fn increase_header_start_offset(&mut self, increase_by: usize, layer: Layer) {
        if layer != LAYER {
            self.header_start_offset += increase_by;
            self.previous_header_information
                .increase_header_start_offset(increase_by, layer);
        }
    }

    #[inline]
    fn decrease_header_start_offset(&mut self, decrease_by: usize, layer: Layer) {
        if layer != LAYER {
            self.header_start_offset -= decrease_by;
            self.previous_header_information
                .decrease_header_start_offset(decrease_by, layer);
        }
    }

    #[inline]
    fn header_length_mut(&mut self, layer: Layer) -> &mut usize {
        if layer == LAYER {
            &mut self.header_length
        } else {
            self.previous_header_information.header_length_mut(layer)
        }
    }

    #[inline]
    fn set_data_length(
        &mut self,
        data_length: usize,
        buffer_length: usize,
    ) -> Result<(), UnexpectedBufferEndError> {
        self.previous_header_information
            .set_data_length(data_length, buffer_length)
    }
}

impl<B, PHI> Payload for DataBuffer<B, Udp<PHI>>
where
    B: AsRef<[u8]>,
    PHI: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn payload(&self) -> &[u8] {
        let payload_start = self.header_length(LAYER);
        &self.data_buffer_starting_at_header(LAYER)[payload_start..]
    }

    #[inline]
    fn payload_length(&self) -> usize {
        self.payload().len()
    }
}

impl<B, PHI> PayloadMut for DataBuffer<B, Udp<PHI>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    PHI: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn payload_mut(&mut self) -> &mut [u8] {
        let payload_start = self.header_length(LAYER);
        &mut self.data_buffer_starting_at_header_mut(LAYER)[payload_start..]
    }
}

impl<B, H> UdpMethods for DataBuffer<B, H>
where
    B: AsRef<[u8]>,
    H: HeaderInformation + HeaderInformationMut + UdpMarker,
    DataBuffer<B, H>: TcpUdpChecksum,
{
}

impl<B, H> UdpMethodsMut for DataBuffer<B, H>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    H: HeaderInformation + HeaderInformationMut + UdpMarker,
    DataBuffer<B, H>: TcpUdpChecksum + UpdateIpLength,
{
}
