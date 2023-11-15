//! TCP implementation and TCP specific errors.

mod error;
mod method_traits;

pub use error::*;
pub use method_traits::*;

#[cfg(all(feature = "remove_checksum", feature = "verify_tcp", kani))]
mod verification;

use crate::data_buffer::traits::HeaderMetadataExtraction;
use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderMetadata, HeaderMetadataMut, Layer,
};
use crate::data_buffer::{
    BufferIntoInner, DataBuffer, EthernetMarker, Ieee802_1QVlanMarker, Ipv4Marker, Ipv6ExtMarker,
    Ipv6Marker, Payload, PayloadMut, TcpMarker,
};
use crate::error::{
    InvalidChecksumError, LengthExceedsAvailableSpaceError, UnexpectedBufferEndError,
};
use crate::internal_utils::{
    check_and_calculate_data_length, header_start_offset_from_phi,
    pseudo_header_checksum_ipv4_internal, pseudo_header_checksum_ipv6_internal,
};
use crate::ipv4::{Ipv4, UpdateIpv4Length};
use crate::ipv6::{Ipv6, UpdateIpv6Length};
use crate::ipv6_extensions::{Ipv6ExtMetaData, Ipv6ExtMetaDataMut, Ipv6Extensions};
use crate::ipv6_extensions::{Ipv6ExtensionIndexOutOfBoundsError, Ipv6ExtensionMetadata};
use crate::no_previous_header::NoPreviousHeader;
use crate::typed_protocol_headers::constants;
use crate::utility_traits::{PseudoHeaderChecksum, UpdateIpLength};

/// TCP metadata.
///
/// Contains meta data about the TCP header in the parsed data buffer.
#[derive(Eq, PartialEq, Hash, Copy, Clone, Debug)]
pub struct Tcp<PHM>
where
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    /// Offset from the start of the non-headroom part of the data buffer.
    header_start_offset: usize,
    /// Header length.
    header_length: usize,
    /// Metadata of the previous header(s).
    previous_header_metadata: PHM,
}

impl<PHM> EthernetMarker for Tcp<PHM> where PHM: HeaderMetadata + HeaderMetadataMut + EthernetMarker {}
impl<PHM> Ieee802_1QVlanMarker for Tcp<PHM> where
    PHM: HeaderMetadata + HeaderMetadataMut + Ieee802_1QVlanMarker
{
}
impl<PHM> Ipv4Marker for Tcp<PHM> where PHM: HeaderMetadata + HeaderMetadataMut + Ipv4Marker {}
impl<PHM> Ipv6Marker for Tcp<PHM> where PHM: HeaderMetadata + HeaderMetadataMut + Ipv6Marker {}
impl<PHM, const MAX_EXTENSIONS: usize> Ipv6ExtMarker<MAX_EXTENSIONS> for Tcp<PHM> where
    PHM: HeaderMetadata + HeaderMetadataMut + Ipv6ExtMarker<MAX_EXTENSIONS>
{
}
impl<PHM> TcpMarker for Tcp<PHM> where PHM: HeaderMetadata + HeaderMetadataMut {}

impl<B, PHM> DataBuffer<B, Tcp<PHM>>
where
    B: AsRef<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut + Copy,
    DataBuffer<B, Tcp<PHM>>: PseudoHeaderChecksum,
{
    /// Parses `buf` and creates a new [`DataBuffer`] for an TCP layer with no previous layers.
    ///
    /// `headroom` indicates the amount of headroom in the provided `buf`.
    /// No checksum can be calculated without underlying header for the pseudo header.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided data buffer is shorter than expected.
    /// - the data offset field value is invalid.
    #[inline]
    pub fn new_without_checksum(
        buf: B,
        headroom: usize,
    ) -> Result<DataBuffer<B, Tcp<NoPreviousHeader>>, ParseTcpError> {
        let lower_layer_data_buffer = DataBuffer::<B, NoPreviousHeader>::new(buf, headroom)?;

        DataBuffer::<B, Tcp<NoPreviousHeader>>::new_from_lower(lower_layer_data_buffer, false)
    }

    /// Consumes the `lower_layer_data_buffer` and creates a new [`DataBuffer`] with an additional
    /// TCP layer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided data buffer is shorter than expected.
    /// - the data offset field value is invalid.
    /// - if `check_tcp_checksum` is true and the checksum is invalid.
    #[inline]
    pub fn new_from_lower(
        lower_layer_data_buffer: impl HeaderMetadata
            + Payload
            + BufferIntoInner<B>
            + HeaderMetadataExtraction<PHM>,
        check_tcp_checksum: bool,
    ) -> Result<DataBuffer<B, Tcp<PHM>>, ParseTcpError> {
        let previous_header_metadata = lower_layer_data_buffer.extract_header_metadata();

        let data_length = check_and_calculate_data_length::<ParseTcpError>(
            lower_layer_data_buffer.payload_length(),
            0,
            HEADER_MIN_LEN,
        )?;
        let data_offset_header_byte = lower_layer_data_buffer.payload()[DATA_OFFSET_BYTE];
        let data_offset_header = usize::from(data_offset_header_byte >> DATA_OFFSET_SHIFT);
        if data_offset_header < *DATA_OFFSET_RANGE.start() {
            return Err(ParseTcpError::DataOffsetHeaderValueTooSmall { data_offset_header });
        }

        let header_length = data_offset_header * 4;

        if header_length > data_length {
            return Err(ParseTcpError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: header_length,
                    actual_length: data_length,
                },
            ));
        }

        let result = DataBuffer {
            header_metadata: Tcp {
                header_start_offset: header_start_offset_from_phi(previous_header_metadata),
                header_length,
                previous_header_metadata: *previous_header_metadata,
            },
            buffer: lower_layer_data_buffer.buffer_into_inner(),
        };

        if check_tcp_checksum {
            let checksum = result.tcp_calculate_checksum();
            if checksum != 0 {
                return Err(ParseTcpError::InvalidChecksum(InvalidChecksumError {
                    calculated_checksum: checksum,
                }));
            }
        }
        Ok(result)
    }
}

impl<B> PseudoHeaderChecksum for DataBuffer<B, Tcp<NoPreviousHeader>>
where
    B: AsRef<[u8]>,
{
    #[inline]
    fn pseudo_header_checksum(&self) -> u64 {
        0
    }
}

impl<B> UpdateIpLength for DataBuffer<B, Tcp<NoPreviousHeader>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    fn update_ip_length(&mut self) {}
}

impl<B, PHM> UpdateIpLength for DataBuffer<B, Tcp<Ipv4<PHM>>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn update_ip_length(&mut self) {
        self.update_ipv4_length();
    }
}

impl<B, PHM> UpdateIpLength for DataBuffer<B, Tcp<Ipv6<PHM>>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn update_ip_length(&mut self) {
        self.update_ipv6_length();
    }
}

impl<B, PHM, const MAX_EXTENSIONS: usize> UpdateIpLength
    for DataBuffer<B, Tcp<Ipv6Extensions<PHM, MAX_EXTENSIONS>>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut + Ipv6Marker,
{
    #[inline]
    fn update_ip_length(&mut self) {
        self.update_ipv6_length();
    }
}

impl<B, PHM> PseudoHeaderChecksum for DataBuffer<B, Tcp<Ipv4<PHM>>>
where
    B: AsRef<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn pseudo_header_checksum(&self) -> u64 {
        pseudo_header_checksum_ipv4_internal(self, constants::TCP)
    }
}

impl<B, PHM> PseudoHeaderChecksum for DataBuffer<B, Tcp<Ipv6<PHM>>>
where
    B: AsRef<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn pseudo_header_checksum(&self) -> u64 {
        pseudo_header_checksum_ipv6_internal(self, constants::TCP)
    }
}

impl<B, PHM, const MAX_EXTENSIONS: usize> PseudoHeaderChecksum
    for DataBuffer<B, Tcp<Ipv6Extensions<PHM, MAX_EXTENSIONS>>>
where
    B: AsRef<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut + Ipv6Marker,
{
    #[inline]
    fn pseudo_header_checksum(&self) -> u64 {
        pseudo_header_checksum_ipv6_internal(self, constants::TCP)
    }
}

impl<PHM> HeaderMetadata for Tcp<PHM>
where
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn headroom_internal(&self) -> usize {
        self.previous_header_metadata.headroom_internal()
    }

    #[inline]
    fn header_start_offset(&self, layer: Layer) -> usize {
        if layer == LAYER {
            self.header_start_offset
        } else {
            self.previous_header_metadata.header_start_offset(layer)
        }
    }

    #[inline]
    fn header_length(&self, layer: Layer) -> usize {
        if layer == LAYER {
            self.header_length
        } else {
            self.previous_header_metadata.header_length(layer)
        }
    }

    #[inline]
    fn layer(&self) -> Layer {
        LAYER
    }

    #[inline]
    fn data_length(&self) -> usize {
        self.previous_header_metadata.data_length()
    }
}

impl<PHM, const MAX_EXTENSIONS: usize> Ipv6ExtMetaData<MAX_EXTENSIONS> for Tcp<PHM>
where
    PHM: HeaderMetadata + HeaderMetadataMut + Ipv6ExtMarker<MAX_EXTENSIONS>,
{
    #[inline]
    fn extensions_array(&self) -> &[Ipv6ExtensionMetadata; MAX_EXTENSIONS] {
        self.previous_header_metadata.extensions_array()
    }

    #[inline]
    fn extension(
        &self,
        idx: usize,
    ) -> Result<Ipv6ExtensionMetadata, Ipv6ExtensionIndexOutOfBoundsError> {
        self.previous_header_metadata.extension(idx)
    }

    #[inline]
    fn extensions_amount(&self) -> usize {
        self.previous_header_metadata.extensions_amount()
    }
}

impl<PHM, const MAX_EXTENSIONS: usize> Ipv6ExtMetaDataMut<MAX_EXTENSIONS> for Tcp<PHM>
where
    PHM: HeaderMetadata + HeaderMetadataMut + Ipv6ExtMarker<MAX_EXTENSIONS>,
{
    #[inline]
    fn extensions_array_mut(&mut self) -> &mut [Ipv6ExtensionMetadata; MAX_EXTENSIONS] {
        self.previous_header_metadata.extensions_array_mut()
    }
}

impl<PHM> HeaderMetadataMut for Tcp<PHM>
where
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn headroom_internal_mut(&mut self) -> &mut usize {
        self.previous_header_metadata.headroom_internal_mut()
    }

    #[inline]
    fn increase_header_start_offset(&mut self, increase_by: usize, layer: Layer) {
        if layer != LAYER {
            self.header_start_offset += increase_by;
            self.previous_header_metadata
                .increase_header_start_offset(increase_by, layer);
        }
    }

    #[inline]
    fn decrease_header_start_offset(&mut self, decrease_by: usize, layer: Layer) {
        if layer != LAYER {
            self.header_start_offset -= decrease_by;
            self.previous_header_metadata
                .decrease_header_start_offset(decrease_by, layer);
        }
    }

    #[inline]
    fn header_length_mut(&mut self, layer: Layer) -> &mut usize {
        if layer == LAYER {
            &mut self.header_length
        } else {
            self.previous_header_metadata.header_length_mut(layer)
        }
    }

    #[inline]
    fn set_data_length(
        &mut self,
        data_length: usize,
        buffer_length: usize,
    ) -> Result<(), LengthExceedsAvailableSpaceError> {
        self.previous_header_metadata
            .set_data_length(data_length, buffer_length)
    }
}

impl<B, PHM> Payload for DataBuffer<B, Tcp<PHM>>
where
    B: AsRef<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut,
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

impl<B, PHM> PayloadMut for DataBuffer<B, Tcp<PHM>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn payload_mut(&mut self) -> &mut [u8] {
        let payload_start = self.header_length(LAYER);
        &mut self.data_buffer_starting_at_header_mut(LAYER)[payload_start..]
    }
}

impl<B, HM> TcpMethods for DataBuffer<B, HM>
where
    B: AsRef<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + TcpMarker,
    DataBuffer<B, HM>: PseudoHeaderChecksum,
{
}

impl<B, HM> TcpMethodsMut for DataBuffer<B, HM>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + TcpMarker,
    DataBuffer<B, HM>: PseudoHeaderChecksum + UpdateIpLength,
{
}

#[cfg(test)]
mod tests {
    use crate::data_buffer::traits::{HeaderMetadata, Layer};
    use crate::data_buffer::{DataBuffer, Payload, PayloadMut};
    use crate::error::{InvalidChecksumError, UnexpectedBufferEndError};
    use crate::ethernet::Eth;
    use crate::ipv4::{Ipv4, Ipv4MethodsMut};
    use crate::ipv6::Ipv6;
    use crate::no_previous_header::NoPreviousHeader;
    use crate::tcp::{ParseTcpError, SetDataOffsetError, Tcp, TcpMethods, TcpMethodsMut};
    use crate::test_utils::copy_into_slice;
    use crate::typed_protocol_headers::InternetProtocolNumber;

    const ETH_IPV4_TCP: [u8; 64] = [
        0x00,
        0x80,
        0x41,
        0xAE,
        0xFD,
        0x7E, // Dst
        0x7E,
        0xFD,
        0xAE,
        0x41,
        0x80,
        0x00, // Src
        0x08,
        0x00, // Ether type
        // Version & IHL
        0x46,
        // DSCP & ECN
        0b0010_1000,
        // Total length
        0x00,
        0x32,
        // Identification
        0x12,
        0x34,
        // Flags & Fragment offset
        0b101_00000,
        0x03,
        // TTL
        0x01,
        // Protocol
        0x06,
        // Header Checksum
        0x06,
        0x61,
        // Source
        0x7f,
        0x00,
        0x00,
        0x1,
        // Destination
        0x7f,
        0x00,
        0x00,
        0x1,
        // Options
        0x02,
        0x04,
        0xFF,
        0xFF,
        // Payload
        // TCP
        // Source port
        0x12,
        0x34,
        // Destination port
        0x45,
        0x67,
        // Sequence number
        0x12,
        0x34,
        0x56,
        0x78,
        // Acknowledgment number
        0x09,
        0x87,
        0x65,
        0x43,
        // Data offset, reserved bits, flags
        0x50,
        0b0101_0101,
        // Window
        0x12,
        0x45,
        // Checksum
        0x19,
        0xB8,
        // Urgent pointer
        0x56,
        0x78,
        // payload
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
    ];

    const ETH_IPV6_TCP: [u8; 80] = [
        0x00,
        0x80,
        0x41,
        0xAE,
        0xFD,
        0x7E, // Dst
        0x7E,
        0xFD,
        0xAE,
        0x41,
        0x80,
        0x00, // Src
        0x86,
        0xDD, // Ether type
        // Version, traffic class and flow label
        0x61,
        0x23,
        0xFF,
        0xFF,
        // Payload Length
        0x00,
        0x1A,
        // Next header
        InternetProtocolNumber::Tcp as u8,
        // Hop limit
        0xFF,
        // Source
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        // Destination
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        // TCP
        // Source port
        0x12,
        0x34,
        // Destination port
        0x45,
        0x67,
        // Sequence number
        0x12,
        0x34,
        0x56,
        0x78,
        // Acknowledgment number
        0x09,
        0x87,
        0x65,
        0x43,
        // Data offset, reserved bits, flags
        0x50,
        0b0101_0101,
        // Window
        0x12,
        0x45,
        // Checksum
        0x17,
        0xBB,
        // Urgent pointer
        0x56,
        0x78,
        // payload
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
    ];

    static IPV4_TCP: [u8; 50] = [
        // Version & IHL
        0x46,
        // DSCP & ECN
        0b0010_1000,
        // Total length
        0x00,
        0x32,
        // Identification
        0x12,
        0x34,
        // Flags & Fragment offset
        0b101_00000,
        0x03,
        // TTL
        0x01,
        // Protocol
        0x06,
        // Header Checksum
        0x06,
        0x61,
        // Source
        0x7f,
        0x00,
        0x00,
        0x1,
        // Destination
        0x7f,
        0x00,
        0x00,
        0x1,
        // Options
        0x02,
        0x04,
        0xFF,
        0xFF,
        // Payload
        // TCP
        // Source port
        0x12,
        0x34,
        // Destination port
        0x45,
        0x67,
        // Sequence number
        0x12,
        0x34,
        0x56,
        0x78,
        // Acknowledgment number
        0x09,
        0x87,
        0x65,
        0x43,
        // Data offset, reserved bits, flags
        0x50,
        0b0101_0101,
        // Window
        0x12,
        0x45,
        // Checksum
        0x19,
        0xB8,
        // Urgent pointer
        0x56,
        0x78,
        // payload
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
    ];

    static IPV6_TCP: [u8; 66] = [
        // Version, traffic class and flow label
        0x61,
        0x23,
        0xFF,
        0xFF,
        // Payload Length
        0x00,
        0x1A,
        // Next header
        InternetProtocolNumber::Tcp as u8,
        // Hop limit
        0xFF,
        // Source
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        // Destination
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        // TCP
        // Source port
        0x12,
        0x34,
        // Destination port
        0x45,
        0x67,
        // Sequence number
        0x12,
        0x34,
        0x56,
        0x78,
        // Acknowledgment number
        0x09,
        0x87,
        0x65,
        0x43,
        // Data offset, reserved bits, flags
        0x50,
        0b0101_0101,
        // Window
        0x12,
        0x45,
        // Checksum
        0x17,
        0xBB,
        // Urgent pointer
        0x56,
        0x78,
        // payload
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
    ];

    #[rustfmt::skip]
    static TCP_PACKET_NO_OPTIONS: [u8;26] = [
        // Source port
        0x12, 0x34,
        // Destination port
        0x45, 0x67,
        // Sequence number
        0x12, 0x34, 0x56, 0x78,
        // Acknowledgment number
        0x09, 0x87, 0x65, 0x43,
        // Data offset, reserved bits, flags
        0x50, 0b0101_0101,
        // Window
        0x12, 0x45,
        // Checksum
        0x12, 0x34,
        // Urgent pointer
        0x56, 0x78,
        // payload
        0xFF, 0xFF,
        0xFF, 0xFF,
        0xFF, 0xFF,
    ];

    #[rustfmt::skip]
    static TCP_PACKET_OPTIONS: [u8;32] = [
        // Source port
        0x12, 0x34,
        // Destination port
        0x45, 0x67,
        // Sequence number
        0x12, 0x34, 0x56, 0x78,
        // Acknowledgment number
        0x09, 0x87, 0x65, 0x43,
        // Data offset, reserved bits, flags
        0x70, 0b0101_0101,
        // Window
        0x12, 0x45,
        // Checksum
        0x12, 0x34,
        // Urgent pointer
        0x56, 0x78,
        // Options
        0xFF, 0xFF,
        0xFF, 0xFF,
        0xFF, 0xFF,
        0xFF, 0xFF,
        // Payload
        0xFF, 0xFF,
        0xFF, 0xFF,
    ];

    #[test]
    fn new() {
        assert!(
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .is_ok()
        );
    }

    #[test]
    fn new_data_buffer_too_short() {
        assert_eq!(
            Err(ParseTcpError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 20,
                    actual_length: 19,
                }
            )),
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(
                &TCP_PACKET_NO_OPTIONS[..19],
                0
            )
        );
        assert_eq!(
            Err(ParseTcpError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 28,
                    actual_length: 27,
                }
            )),
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(
                &TCP_PACKET_OPTIONS[..27],
                0
            )
        );
    }

    #[test]
    fn new_headroom_out_of_range() {
        assert_eq!(
            Err(ParseTcpError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 290,
                    actual_length: 26,
                }
            )),
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(
                &TCP_PACKET_NO_OPTIONS,
                290
            )
        );
    }

    #[test]
    fn new_data_offset_header() {
        let mut data = TCP_PACKET_NO_OPTIONS;
        data[12] = 0x40;
        assert_eq!(
            Err(ParseTcpError::DataOffsetHeaderValueTooSmall {
                data_offset_header: 4
            }),
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(&data, 0)
        );

        let mut data = TCP_PACKET_NO_OPTIONS;
        data[12] = 0xF0;
        assert_eq!(
            Err(ParseTcpError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 60,
                    actual_length: 26,
                }
            )),
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(&data, 0)
        );
    }

    // Verified by hand
    #[test]
    fn checksum() {
        let ipv4 = DataBuffer::<_, Ipv4<NoPreviousHeader>>::new(IPV4_TCP, 0, true).unwrap();
        assert!(DataBuffer::<_, Tcp<_>>::new_from_lower(ipv4, true).is_ok());

        let mut data = IPV4_TCP;
        data[40] = 0xFF;
        let ipv4 = DataBuffer::<_, Ipv4<NoPreviousHeader>>::new(data, 0, true).unwrap();
        assert_eq!(
            Err(ParseTcpError::InvalidChecksum(InvalidChecksumError {
                calculated_checksum: 6655,
            })),
            DataBuffer::<_, Tcp<_>>::new_from_lower(ipv4, true)
        );

        let ipv6 = DataBuffer::<_, Ipv6<NoPreviousHeader>>::new(IPV6_TCP, 0).unwrap();
        assert!(DataBuffer::<_, Tcp<_>>::new_from_lower(ipv6, true).is_ok());

        let mut data = IPV6_TCP;
        data[40] = 0xFF;
        let ipv6 = DataBuffer::<_, Ipv6<NoPreviousHeader>>::new(data, 0).unwrap();
        assert_eq!(
            Err(ParseTcpError::InvalidChecksum(InvalidChecksumError {
                calculated_checksum: 4863,
            })),
            DataBuffer::<_, Tcp<_>>::new_from_lower(ipv6, true)
        );
    }

    #[test]
    fn tcp_source_port() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0x1234, tcp_packet.tcp_source_port());
    }

    #[test]
    fn tcp_destination_port() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0x4567, tcp_packet.tcp_destination_port());
    }

    #[test]
    fn tcp_sequence_number() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0x12_34_56_78, tcp_packet.tcp_sequence_number());
    }

    #[test]
    fn tcp_acknowledgment_number() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0x09_87_65_43, tcp_packet.tcp_acknowledgment_number());
    }

    #[test]
    fn tcp_data_offset() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(5, tcp_packet.tcp_data_offset());
    }

    #[test]
    fn tcp_reserved_bits() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0, tcp_packet.tcp_reserved_bits());
    }

    #[test]
    fn tcp_flags() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0b0101_0101, tcp_packet.tcp_flags());
    }

    #[test]
    fn tcp_congestion_window_reduced_flag() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert!(!tcp_packet.tcp_congestion_window_reduced_flag());
    }

    #[test]
    fn tcp_ecn_echo_flag() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert!(tcp_packet.tcp_ecn_echo_flag());
    }

    #[test]
    fn tcp_urgent_pointer_flag() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert!(!tcp_packet.tcp_urgent_pointer_flag());
    }

    #[test]
    fn tcp_acknowledgement_flag() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert!(tcp_packet.tcp_acknowledgement_flag());
    }

    #[test]
    fn tcp_push_flag() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert!(!tcp_packet.tcp_push_flag());
    }

    #[test]
    fn tcp_reset_flag() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert!(tcp_packet.tcp_reset_flag());
    }

    #[test]
    fn tcp_synchronize_flag() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert!(!tcp_packet.tcp_synchronize_flag());
    }

    #[test]
    fn tcp_fin_flag() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert!(tcp_packet.tcp_fin_flag());
    }

    #[test]
    fn tcp_window_size() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0x1245, tcp_packet.tcp_window_size());
    }

    #[test]
    fn tcp_checksum() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0x1234, tcp_packet.tcp_checksum());
    }

    #[test]
    fn tcp_urgent_pointer() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0x5678, tcp_packet.tcp_urgent_pointer());
    }

    #[test]
    fn tcp_options() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(None, tcp_packet.tcp_options());

        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_OPTIONS, 0)
                .unwrap();
        assert_eq!(Some([0xFF; 8].as_slice()), tcp_packet.tcp_options());
    }

    #[test]
    fn payload() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(&[0xFF; 6], tcp_packet.payload());
    }

    #[test]
    fn payload_mut() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(&mut [0xFF; 6], tcp_packet.payload_mut());
    }

    #[test]
    fn payload_length() {
        let tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(6, tcp_packet.payload_length());
    }

    #[test]
    fn set_tcp_source_port() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0x1234, tcp_packet.tcp_source_port());
        tcp_packet.set_tcp_source_port(0x8989);
        assert_eq!(0x8989, tcp_packet.tcp_source_port());
    }

    #[test]
    fn set_tcp_destination_port() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0x4567, tcp_packet.tcp_destination_port());
        tcp_packet.set_tcp_destination_port(0x6767);
        assert_eq!(0x6767, tcp_packet.tcp_destination_port());
    }

    #[test]
    fn set_tcp_sequence_number() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0x12_34_56_78, tcp_packet.tcp_sequence_number());
        tcp_packet.set_tcp_sequence_number(0x09_87_65_43);
        assert_eq!(0x09_87_65_43, tcp_packet.tcp_sequence_number());
    }

    #[test]
    fn set_tcp_acknowledgement_number() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0x09_87_65_43, tcp_packet.tcp_acknowledgment_number());
        tcp_packet.set_tcp_acknowledgement_number(0x12_34_56_77);
        assert_eq!(0x12_34_56_77, tcp_packet.tcp_acknowledgment_number());
    }

    #[test]
    fn set_tcp_reserved_bits() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0, tcp_packet.tcp_reserved_bits());
        tcp_packet.set_tcp_reserved_bits(0xFF);
        assert_eq!(0b0000_1111, tcp_packet.tcp_reserved_bits());
    }

    #[test]
    fn set_tcp_flags() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0b0101_0101, tcp_packet.tcp_flags());
        tcp_packet.set_tcp_flags(0b1010_1010);
        assert_eq!(0b1010_1010, tcp_packet.tcp_flags());
    }

    #[test]
    fn set_tcp_congestion_window_reduced_flag() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert!(!tcp_packet.tcp_congestion_window_reduced_flag());
        tcp_packet.set_tcp_congestion_window_reduced_flag(true);
        assert!(tcp_packet.tcp_congestion_window_reduced_flag());
    }

    #[test]
    fn set_tcp_ecn_echo_flag() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert!(tcp_packet.tcp_ecn_echo_flag());
        tcp_packet.set_tcp_ecn_echo_flag(false);
        assert!(!tcp_packet.tcp_ecn_echo_flag());
    }

    #[test]
    fn set_tcp_urgent_pointer_flag() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert!(!tcp_packet.tcp_urgent_pointer_flag());
        tcp_packet.set_tcp_urgent_pointer_flag(true);
        assert!(tcp_packet.tcp_urgent_pointer_flag());
    }

    #[test]
    fn set_tcp_acknowledgement_flag() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert!(tcp_packet.tcp_acknowledgement_flag());
        tcp_packet.set_tcp_acknowledgement_flag(false);
        assert!(!tcp_packet.tcp_acknowledgement_flag());
    }

    #[test]
    fn set_tcp_push_flag() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert!(!tcp_packet.tcp_push_flag());
        tcp_packet.set_tcp_push_flag(true);
        assert!(tcp_packet.tcp_push_flag());
    }

    #[test]
    fn set_tcp_reset_flag() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert!(tcp_packet.tcp_reset_flag());
        tcp_packet.set_tcp_reset_flag(false);
        assert!(!tcp_packet.tcp_reset_flag());
    }

    #[test]
    fn set_tcp_synchronize_flag() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert!(!tcp_packet.tcp_synchronize_flag());
        tcp_packet.set_tcp_synchronize_flag(true);
        assert!(tcp_packet.tcp_synchronize_flag());
    }

    #[test]
    fn set_tcp_fin_flag() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert!(tcp_packet.tcp_fin_flag());
        tcp_packet.set_tcp_fin_flag(false);
        assert!(!tcp_packet.tcp_fin_flag());
    }

    #[test]
    fn set_tcp_window_size() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0x1245, tcp_packet.tcp_window_size());
        tcp_packet.set_tcp_window_size(0x5432);
        assert_eq!(0x5432, tcp_packet.tcp_window_size());
    }

    #[test]
    fn set_tcp_checksum() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0x1234, tcp_packet.tcp_checksum());
        tcp_packet.set_tcp_checksum(0x5656);
        assert_eq!(0x5656, tcp_packet.tcp_checksum());
    }

    #[test]
    fn set_tcp_urgent_pointer() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(0x5678, tcp_packet.tcp_urgent_pointer());
        tcp_packet.set_tcp_urgent_pointer(0x0909);
        assert_eq!(0x0909, tcp_packet.tcp_urgent_pointer());
    }

    #[test]
    fn update_tcp_checksum() {
        let mut data = IPV4_TCP;
        data[40] = 0;

        let ipv4 = DataBuffer::<_, Ipv4<NoPreviousHeader>>::new(data, 0, true).unwrap();
        let mut tcp_packet = DataBuffer::<_, Tcp<_>>::new_from_lower(ipv4, false).unwrap();

        assert_eq!(0xB8, tcp_packet.tcp_checksum());
        tcp_packet.update_tcp_checksum();
        assert_eq!(0x19B8, tcp_packet.tcp_checksum());

        let mut data = IPV6_TCP;
        data[56] = 0;

        let ipv6 = DataBuffer::<_, Ipv6<NoPreviousHeader>>::new(data, 0).unwrap();
        let mut tcp_packet = DataBuffer::<_, Tcp<_>>::new_from_lower(ipv6, false).unwrap();

        assert_eq!(0xBB, tcp_packet.tcp_checksum());
        tcp_packet.update_tcp_checksum();
        assert_eq!(0x17BB, tcp_packet.tcp_checksum());
    }

    #[test]
    fn tcp_options_mut() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(None, tcp_packet.tcp_options_mut());

        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_OPTIONS, 0)
                .unwrap();
        assert_eq!(Some([0xFF; 8].as_mut()), tcp_packet.tcp_options_mut());
    }

    #[test]
    fn set_tcp_data_offset() {
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(TCP_PACKET_NO_OPTIONS, 0)
                .unwrap();
        assert_eq!(None, tcp_packet.tcp_options_mut());

        assert_eq!(
            Err(SetDataOffsetError::InvalidDataOffset { data_offset: 4 }),
            tcp_packet.set_tcp_data_offset(4)
        );
        assert_eq!(
            Err(SetDataOffsetError::InvalidDataOffset { data_offset: 16 }),
            tcp_packet.set_tcp_data_offset(16)
        );

        let mut data = [0xFF_u8; 66];
        copy_into_slice(&mut data, &TCP_PACKET_NO_OPTIONS, 40);
        let mut tcp_packet =
            DataBuffer::<_, Tcp<NoPreviousHeader>>::new_without_checksum(data, 40).unwrap();

        assert_eq!(5, tcp_packet.tcp_data_offset());
        assert_eq!(None, tcp_packet.tcp_options());
        tcp_packet.set_tcp_data_offset(15).unwrap();
        tcp_packet
            .tcp_options_mut()
            .unwrap()
            .copy_from_slice(&[0xFF; 40]);
        assert_eq!(Some([0xFF; 40].as_slice()), tcp_packet.tcp_options());
        assert_eq!(15, tcp_packet.tcp_data_offset());

        tcp_packet.set_tcp_data_offset(10).unwrap();
        tcp_packet
            .tcp_options_mut()
            .unwrap()
            .copy_from_slice(&[0x00; 20]);
        assert_eq!(Some([0x00; 20].as_slice()), tcp_packet.tcp_options());
        assert_eq!(10, tcp_packet.tcp_data_offset());

        assert_eq!(&[0xFF; 6], tcp_packet.payload_mut());
    }

    #[test]
    fn set_tcp_data_offset_ipv4() {
        let ethernet = DataBuffer::<_, Eth>::new(ETH_IPV4_TCP, 0).unwrap();
        let ipv4 = DataBuffer::<_, Ipv4<Eth>>::new_from_lower(ethernet, true).unwrap();

        let mut tcp_packet = DataBuffer::<_, Tcp<Ipv4<Eth>>>::new_from_lower(ipv4, true).unwrap();
        assert_eq!(None, tcp_packet.tcp_options_mut());

        assert_eq!(
            Err(SetDataOffsetError::InvalidDataOffset { data_offset: 4 }),
            tcp_packet.set_tcp_data_offset(4)
        );
        assert_eq!(
            Err(SetDataOffsetError::InvalidDataOffset { data_offset: 16 }),
            tcp_packet.set_tcp_data_offset(16)
        );

        let mut data = [0xFF_u8; 110];
        copy_into_slice(&mut data, &ETH_IPV4_TCP, 40);
        let ethernet = DataBuffer::<_, Eth>::new(data, 40).unwrap();
        let ipv4 = DataBuffer::<_, Ipv4<Eth>>::new_from_lower(ethernet, true).unwrap();

        let mut tcp_packet = DataBuffer::<_, Tcp<Ipv4<Eth>>>::new_from_lower(ipv4, true).unwrap();

        assert_eq!(&[0xFF; 6], tcp_packet.payload_mut());
        assert_eq!(5, tcp_packet.tcp_data_offset());
        assert_eq!(None, tcp_packet.tcp_options());
        tcp_packet.set_tcp_data_offset(15).unwrap();
        tcp_packet
            .tcp_options_mut()
            .unwrap()
            .copy_from_slice(&[0xFF; 40]);
        assert_eq!(Some([0xFF; 40].as_slice()), tcp_packet.tcp_options());
        assert_eq!(15, tcp_packet.tcp_data_offset());

        tcp_packet.set_tcp_data_offset(10).unwrap();
        tcp_packet
            .tcp_options_mut()
            .unwrap()
            .copy_from_slice(&[0x00; 20]);
        assert_eq!(Some([0x00; 20].as_slice()), tcp_packet.tcp_options());
        assert_eq!(10, tcp_packet.tcp_data_offset());

        assert_eq!(&[0xFF; 6], tcp_packet.payload_mut());
    }

    #[test]
    fn set_tcp_data_offset_ipv6() {
        let ethernet = DataBuffer::<_, Eth>::new(ETH_IPV6_TCP, 0).unwrap();
        let ipv6 = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(ethernet).unwrap();

        let mut tcp_packet = DataBuffer::<_, Tcp<Ipv6<Eth>>>::new_from_lower(ipv6, true).unwrap();
        assert_eq!(None, tcp_packet.tcp_options_mut());

        assert_eq!(
            Err(SetDataOffsetError::InvalidDataOffset { data_offset: 4 }),
            tcp_packet.set_tcp_data_offset(4)
        );
        assert_eq!(
            Err(SetDataOffsetError::InvalidDataOffset { data_offset: 16 }),
            tcp_packet.set_tcp_data_offset(16)
        );

        let mut data = [0xFF_u8; 150];
        copy_into_slice(&mut data, &ETH_IPV6_TCP, 40);
        let ethernet = DataBuffer::<_, Eth>::new(data, 40).unwrap();
        let ipv6 = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(ethernet).unwrap();

        let mut tcp_packet = DataBuffer::<_, Tcp<Ipv6<Eth>>>::new_from_lower(ipv6, true).unwrap();
        assert_eq!(&[0xFF; 6], tcp_packet.payload_mut());

        assert_eq!(5, tcp_packet.tcp_data_offset());
        assert_eq!(None, tcp_packet.tcp_options());
        tcp_packet.set_tcp_data_offset(15).unwrap();
        tcp_packet
            .tcp_options_mut()
            .unwrap()
            .copy_from_slice(&[0xFF; 40]);
        assert_eq!(Some([0xFF; 40].as_slice()), tcp_packet.tcp_options());
        assert_eq!(15, tcp_packet.tcp_data_offset());

        tcp_packet.set_tcp_data_offset(10).unwrap();
        tcp_packet
            .tcp_options_mut()
            .unwrap()
            .copy_from_slice(&[0x00; 20]);
        assert_eq!(Some([0x00; 20].as_slice()), tcp_packet.tcp_options());
        assert_eq!(10, tcp_packet.tcp_data_offset());

        assert_eq!(&[0xFF; 6], tcp_packet.payload_mut());
    }

    // Checks whether the header start offset is changed correctly if a lower layer changes its size
    #[test]
    fn set_ipv4_ihl() {
        let mut data = [0; 124];
        copy_into_slice(&mut data, &ETH_IPV4_TCP, 60);
        let ethernet = DataBuffer::<_, Eth>::new(data, 60).unwrap();
        let ipv4 = DataBuffer::<_, Ipv4<Eth>>::new_from_lower(ethernet, true).unwrap();

        let mut tcp_packet = DataBuffer::<_, Tcp<Ipv4<Eth>>>::new_from_lower(ipv4, true).unwrap();

        let flags = tcp_packet.tcp_flags();
        assert_eq!(38, tcp_packet.header_start_offset(Layer::Tcp));
        tcp_packet.set_ipv4_ihl(15).unwrap();
        assert_eq!(74, tcp_packet.header_start_offset(Layer::Tcp));
        assert_eq!(flags, tcp_packet.tcp_flags());
        tcp_packet.set_ipv4_ihl(5).unwrap();
        assert_eq!(34, tcp_packet.header_start_offset(Layer::Tcp));
        assert_eq!(flags, tcp_packet.tcp_flags());
    }
}
