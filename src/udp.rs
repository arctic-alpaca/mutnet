//! UDP implementation and UDP specific errors.

mod error;
mod method_traits;

pub use error::*;
pub use method_traits::*;

#[cfg(all(feature = "remove_checksum", feature = "verify_udp", kani))]
mod verification;

use crate::data_buffer::traits::HeaderMetadataExtraction;
use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderMetadata, HeaderMetadataMut, Layer,
};
use crate::data_buffer::{
    BufferIntoInner, DataBuffer, EthernetMarker, Ieee802_1QVlanMarker, Ipv4Marker, Ipv6ExtMarker,
    Ipv6Marker, Payload, PayloadMut, UdpMarker,
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

/// UDP metadata.
///
/// Contains meta data about the UDP header in the parsed data buffer.
#[allow(private_bounds)]
#[derive(Eq, PartialEq, Hash, Copy, Clone, Debug)]
pub struct Udp<PHM>
where
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    header_start_offset: usize,
    header_length: usize,
    previous_header_metadata: PHM,
}

impl<PHM> EthernetMarker for Udp<PHM> where PHM: HeaderMetadata + HeaderMetadataMut + EthernetMarker {}
impl<PHM> Ieee802_1QVlanMarker for Udp<PHM> where
    PHM: HeaderMetadata + HeaderMetadataMut + Ieee802_1QVlanMarker
{
}
impl<PHM> Ipv4Marker for Udp<PHM> where PHM: HeaderMetadata + HeaderMetadataMut + Ipv4Marker {}
impl<PHM> Ipv6Marker for Udp<PHM> where PHM: HeaderMetadata + HeaderMetadataMut + Ipv6Marker {}
impl<PHM, const MAX_EXTENSIONS: usize> Ipv6ExtMarker<MAX_EXTENSIONS> for Udp<PHM> where
    PHM: HeaderMetadata + HeaderMetadataMut + Ipv6ExtMarker<MAX_EXTENSIONS>
{
}
impl<PHM> UdpMarker for Udp<PHM> where PHM: HeaderMetadata + HeaderMetadataMut {}

#[allow(private_bounds)]
impl<B, PHM> DataBuffer<B, Udp<PHM>>
where
    B: AsRef<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut + Copy,
    DataBuffer<B, Udp<PHM>>: PseudoHeaderChecksum,
{
    /// Parses `buf` and creates a new [`DataBuffer`] for an UDP layer with no previous layers.
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
    pub fn parse_udp_alone(
        buf: B,
        headroom: usize,
    ) -> Result<DataBuffer<B, Udp<NoPreviousHeader>>, ParseUdpError> {
        let lower_layer_data_buffer = DataBuffer::<B, NoPreviousHeader>::new(buf, headroom)?;

        DataBuffer::<B, Udp<NoPreviousHeader>>::parse_udp_layer(lower_layer_data_buffer, false)
    }

    /// Consumes the `lower_layer_data_buffer` and creates a new [`DataBuffer`] with an additional
    /// UDP layer.
    ///
    /// # Note
    ///
    /// Inconsistencies between the IP payload length allocated for the UDP datagram and the UDP
    /// length are permissible as long as the indicated IP payload length is larger than the UDP
    /// length.
    /// <https://datatracker.ietf.org/doc/html/rfc768>
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-tsvwg-udp-options-01#section-9>
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided data buffer is shorter than expected.
    /// - the length field value is invalid.
    /// - if `check_udp_checksum` is true and the checksum is invalid.
    #[inline]
    pub fn parse_udp_layer(
        lower_layer_data_buffer: impl HeaderMetadata
            + Payload
            + BufferIntoInner<B>
            + HeaderMetadataExtraction<PHM>,
        check_udp_checksum: bool,
    ) -> Result<DataBuffer<B, Udp<PHM>>, ParseUdpError> {
        let previous_header_metadata = lower_layer_data_buffer.extract_header_metadata();

        let data_length = check_and_calculate_data_length::<ParseUdpError>(
            lower_layer_data_buffer.payload_length(),
            0,
            HEADER_MIN_LEN,
        )?;

        let length_header = usize::from(u16::from_be_bytes(
            lower_layer_data_buffer.payload()[LENGTH]
                .try_into()
                .unwrap(),
        ));

        if length_header < HEADER_MIN_LEN {
            return Err(ParseUdpError::LengthHeaderTooSmall { length_header });
        }

        if length_header > data_length {
            return Err(ParseUdpError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: length_header,
                    actual_length: data_length,
                },
            ));
        }

        let result = DataBuffer {
            header_metadata: Udp {
                header_start_offset: header_start_offset_from_phi(previous_header_metadata),
                header_length: HEADER_MIN_LEN,
                previous_header_metadata: *previous_header_metadata,
            },
            buffer: lower_layer_data_buffer.buffer_into_inner(),
        };

        if check_udp_checksum {
            let checksum = result.udp_calculate_checksum();
            if checksum != 0 {
                return Err(ParseUdpError::InvalidChecksum(InvalidChecksumError {
                    calculated_checksum: checksum,
                }));
            }
        }

        Ok(result)
    }
}

impl<B> PseudoHeaderChecksum for DataBuffer<B, Udp<NoPreviousHeader>>
where
    B: AsRef<[u8]>,
{
    #[inline]
    fn pseudo_header_checksum(&self) -> u64 {
        0
    }
}

impl<B> UpdateIpLength for DataBuffer<B, Udp<NoPreviousHeader>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    fn update_ip_length(&mut self) {}
}

impl<B, PHM> UpdateIpLength for DataBuffer<B, Udp<Ipv4<PHM>>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn update_ip_length(&mut self) {
        self.update_ipv4_length();
    }
}

impl<B, PHM> UpdateIpLength for DataBuffer<B, Udp<Ipv6<PHM>>>
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
    for DataBuffer<B, Udp<Ipv6Extensions<PHM, MAX_EXTENSIONS>>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut + Ipv6Marker,
{
    #[inline]
    fn update_ip_length(&mut self) {
        self.update_ipv6_length();
    }
}

impl<B, PHM> PseudoHeaderChecksum for DataBuffer<B, Udp<Ipv4<PHM>>>
where
    B: AsRef<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn pseudo_header_checksum(&self) -> u64 {
        pseudo_header_checksum_ipv4_internal(self, constants::UDP)
    }
}

impl<B, PHM> PseudoHeaderChecksum for DataBuffer<B, Udp<Ipv6<PHM>>>
where
    B: AsRef<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn pseudo_header_checksum(&self) -> u64 {
        pseudo_header_checksum_ipv6_internal(self, constants::UDP)
    }
}

impl<B, PHM, const MAX_EXTENSIONS: usize> PseudoHeaderChecksum
    for DataBuffer<B, Udp<Ipv6Extensions<PHM, MAX_EXTENSIONS>>>
where
    B: AsRef<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut + Ipv6Marker,
{
    #[inline]
    fn pseudo_header_checksum(&self) -> u64 {
        pseudo_header_checksum_ipv6_internal(self, constants::UDP)
    }
}

impl<PHM> HeaderMetadata for Udp<PHM>
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

impl<PHM, const MAX_EXTENSIONS: usize> Ipv6ExtMetaData<MAX_EXTENSIONS> for Udp<PHM>
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

impl<PHM, const MAX_EXTENSIONS: usize> Ipv6ExtMetaDataMut<MAX_EXTENSIONS> for Udp<PHM>
where
    PHM: HeaderMetadata + HeaderMetadataMut + Ipv6ExtMarker<MAX_EXTENSIONS>,
{
    #[inline]
    fn extensions_array_mut(&mut self) -> &mut [Ipv6ExtensionMetadata; MAX_EXTENSIONS] {
        self.previous_header_metadata.extensions_array_mut()
    }
}

impl<PHM> HeaderMetadataMut for Udp<PHM>
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

impl<B, PHM> Payload for DataBuffer<B, Udp<PHM>>
where
    B: AsRef<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut,
    DataBuffer<B, Udp<PHM>>: PseudoHeaderChecksum,
{
    #[inline]
    fn payload(&self) -> &[u8] {
        let payload_start = self.header_length(LAYER);
        let payload_end = usize::from(self.udp_length());
        &self.data_buffer_starting_at_header(LAYER)[payload_start..payload_end]
    }

    #[inline]
    fn payload_length(&self) -> usize {
        self.payload().len()
    }
}

impl<B, PHM> PayloadMut for DataBuffer<B, Udp<PHM>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut,
    DataBuffer<B, Udp<PHM>>: PseudoHeaderChecksum,
{
    #[inline]
    fn payload_mut(&mut self) -> &mut [u8] {
        let payload_start = self.header_length(LAYER);
        let payload_end = usize::from(self.udp_length());
        &mut self.data_buffer_starting_at_header_mut(LAYER)[payload_start..payload_end]
    }
}

impl<B, HM> UdpMethods for DataBuffer<B, HM>
where
    B: AsRef<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + UdpMarker,
    DataBuffer<B, HM>: PseudoHeaderChecksum,
{
}

impl<B, HM> UdpMethodsMut for DataBuffer<B, HM>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + UdpMarker,
    DataBuffer<B, HM>: PseudoHeaderChecksum + UpdateIpLength,
{
}

#[cfg(test)]
mod tests {
    use crate::data_buffer::{DataBuffer, HeaderMetadata, Layer, Payload, PayloadMut};
    use crate::error::{InvalidChecksumError, UnexpectedBufferEndError};
    use crate::ethernet::Eth;
    use crate::ipv4::{Ipv4, Ipv4MethodsMut};
    use crate::ipv6::{Ipv6, Ipv6Methods, Ipv6MethodsMut};
    use crate::ipv6_extensions::Ipv6Extensions;
    use crate::no_previous_header::NoPreviousHeader;
    use crate::test_utils::copy_into_slice;
    use crate::typed_protocol_headers::RoutingType;
    use crate::typed_protocol_headers::{InternetProtocolNumber, Ipv6ExtensionType};
    use crate::udp::{ParseUdpError, SetLengthError, Udp, UdpMethods, UdpMethodsMut};

    const ETH_IPV6_EXT_UDP: [u8; 92] = [
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
        0x26,
        // Next header
        Ipv6ExtensionType::HopByHop as u8,
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
        0xDD,
        // Payload
        Ipv6ExtensionType::Routing as u8,
        0, // Length
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        Ipv6ExtensionType::DestinationOptions as u8,
        0,                              // Length
        RoutingType::SourceRoute as u8, // Routing type
        5,                              // Segments left
        0xBB,                           // Data
        0xBB,                           // Data
        0xBB,                           // Data
        0xBB,                           // Data
        InternetProtocolNumber::Udp as u8,
        0, // Length
        0xCC,
        0xCC,
        0xCC,
        0xCC,
        0xCC,
        0xCC,
        // UDP
        // Source port
        0x12,
        0x34,
        // Destination port
        0x45,
        0x67,
        // Length
        0x00,
        0x0C,
        // Checksum
        0xA8,
        0x5B,
        // Payload
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
    ];

    static UDP: [u8; 14] = [
        // Source port
        0x12, 0x34, // Destination port
        0x45, 0x67, // Length
        0x00, 0x0C, // Checksum
        0xAB, 0xCD, // Payload
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    const ETH_IPV4_UDP: [u8; 52] = [
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
        // UDP
        // Source port
        0x12,
        0x34,
        // Destination port
        0x45,
        0x67,
        // Length
        0x00,
        0x0C,
        // Checksum
        0xAA,
        0x2A,
        // Payload
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
    ];

    #[test]
    fn new() {
        assert!(
            DataBuffer::<_, Udp<Ipv6Extensions<Ipv6<Eth>, 10>>>::parse_udp_layer(
                DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, 10>>::parse_ipv6_extensions_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(ETH_IPV6_EXT_UDP, 0).unwrap(),
                    )
                    .unwrap(),
                    Ipv6ExtensionType::Routing,
                )
                .unwrap()
                .0,
                true,
            )
            .is_ok()
        );

        assert!(DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(UDP, 0).is_ok());
    }

    #[test]
    fn new_data_buffer_too_short() {
        assert!(
            DataBuffer::<_, Udp<Ipv6Extensions<Ipv6<Eth>, 10>>>::parse_udp_layer(
                DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, 10>>::parse_ipv6_extensions_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(ETH_IPV6_EXT_UDP, 0).unwrap(),
                    )
                    .unwrap(),
                    Ipv6ExtensionType::Routing,
                )
                .unwrap()
                .0,
                true,
            )
            .is_ok()
        );

        // Check min length
        assert_eq!(
            Err(ParseUdpError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 8,
                    actual_length: 7,
                }
            )),
            DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(&UDP[..7], 0)
        );
    }

    #[test]
    fn new_ipv6_payload_shorter_than_udp_length() {
        let mut ipv6 = DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, 10>>::parse_ipv6_extensions_layer(
            DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(ETH_IPV6_EXT_UDP, 0).unwrap(),
            )
            .unwrap(),
            Ipv6ExtensionType::Routing,
        )
        .unwrap()
        .0;
        ipv6.set_ipv6_payload_length(31).unwrap();
        assert_eq!(
            Err(ParseUdpError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 8,
                    actual_length: 7,
                }
            )),
            DataBuffer::<_, Udp<_>>::parse_udp_layer(ipv6.clone(), false)
        );
        ipv6.set_ipv6_payload_length(32).unwrap();
        assert_eq!(
            Err(ParseUdpError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 12,
                    actual_length: 8,
                }
            )),
            DataBuffer::<_, Udp<_>>::parse_udp_layer(ipv6.clone(), false)
        );
    }

    #[test]
    fn new_invalid_length_header() {
        let mut data = UDP;
        data[5] = 7;
        assert_eq!(
            Err(ParseUdpError::LengthHeaderTooSmall { length_header: 7 }),
            DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(data, 0,)
        );
    }

    #[test]
    fn new_headroom_out_of_range() {
        assert_eq!(
            Err(ParseUdpError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 500,
                    actual_length: 14,
                }
            )),
            DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(UDP, 500,)
        );
    }

    #[test]
    fn new_payload_length_too_large() {
        let mut data = UDP;
        data[4] = 0xFF;
        assert_eq!(
            Err(ParseUdpError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 65292,
                    actual_length: 14,
                }
            )),
            DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(data, 0,)
        );
    }

    #[test]
    fn new_invalid_checksum() {
        let mut ipv6 = DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, 10>>::parse_ipv6_extensions_layer(
            DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(ETH_IPV6_EXT_UDP, 0).unwrap(),
            )
            .unwrap(),
            Ipv6ExtensionType::Routing,
        )
        .unwrap()
        .0;
        ipv6.set_ipv6_destination([0; 16]);
        assert_eq!(
            Err(ParseUdpError::InvalidChecksum(InvalidChecksumError {
                calculated_checksum: 65501
            })),
            DataBuffer::<_, Udp<_>>::parse_udp_layer(ipv6.clone(), true)
        );
    }

    #[test]
    fn udp_source_port() {
        let udp_datagram = DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(UDP, 0).unwrap();

        assert_eq!(0x1234, udp_datagram.udp_source_port());
    }

    #[test]
    fn udp_destination_port() {
        let udp_datagram = DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(UDP, 0).unwrap();

        assert_eq!(0x4567, udp_datagram.udp_destination_port());
    }

    #[test]
    fn udp_length() {
        let udp_datagram = DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(UDP, 0).unwrap();

        assert_eq!(0xC, udp_datagram.udp_length());
    }

    #[test]
    fn udp_checksum() {
        let udp_datagram = DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(UDP, 0).unwrap();

        assert_eq!(0xABCD, udp_datagram.udp_checksum());
    }

    #[test]
    fn udp_calculate_checksum() {
        let udp_datagram = DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(UDP, 0).unwrap();

        assert_eq!(0xFC8A, udp_datagram.udp_calculate_checksum());
    }

    #[test]
    fn payload() {
        let udp_datagram = DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(UDP, 0).unwrap();

        assert_eq!(&[0xFF; 4], udp_datagram.payload());
    }

    #[test]
    fn payload_mut() {
        let mut udp_datagram =
            DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(UDP, 0).unwrap();

        assert_eq!(&[0xFF; 4], udp_datagram.payload_mut());
    }

    #[test]
    fn payload_length() {
        let udp_datagram = DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(UDP, 0).unwrap();

        assert_eq!(4, udp_datagram.payload_length());
    }

    #[test]
    fn set_udp_source_port() {
        let mut udp_datagram =
            DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(UDP, 0).unwrap();

        assert_eq!(0x1234, udp_datagram.udp_source_port());
        udp_datagram.set_udp_source_port(0xFFDD);
        assert_eq!(0xFFDD, udp_datagram.udp_source_port());
    }

    #[test]
    fn set_udp_destination_port() {
        let mut udp_datagram =
            DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(UDP, 0).unwrap();

        assert_eq!(0x4567, udp_datagram.udp_destination_port());
        udp_datagram.set_udp_destination_port(0xFFDD);
        assert_eq!(0xFFDD, udp_datagram.udp_destination_port());
    }

    #[test]
    fn set_udp_length() {
        let mut udp_datagram =
            DataBuffer::<_, Udp<Ipv6Extensions<Ipv6<Eth>, 10>>>::parse_udp_layer(
                DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, 10>>::parse_ipv6_extensions_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(ETH_IPV6_EXT_UDP, 0).unwrap(),
                    )
                    .unwrap(),
                    Ipv6ExtensionType::Routing,
                )
                .unwrap()
                .0,
                true,
            )
            .unwrap();

        assert_eq!(0xC, udp_datagram.udp_length());
        // IPv6 length includes two more bytes than the UDP length, this is why the ipv6 payload length
        // shrinks by one when the UDP length is incremented by one.
        assert_eq!(0x26, udp_datagram.ipv6_payload_length());
        assert_eq!(92, udp_datagram.data_length());
        assert_eq!(&[0xFF; 4], udp_datagram.payload());
        udp_datagram.set_udp_length(0xD).unwrap();
        assert_eq!(0xD, udp_datagram.udp_length());
        assert_eq!(0x25, udp_datagram.ipv6_payload_length());
        assert_eq!(91, udp_datagram.data_length());
        assert_eq!(&[0xFF; 5], udp_datagram.payload());

        assert_eq!(
            Err(SetLengthError::LengthTooSmall { length: 7 }),
            udp_datagram.set_udp_length(0x7)
        );
        assert_eq!(0xD, udp_datagram.udp_length());
        assert_eq!(0x25, udp_datagram.ipv6_payload_length());
        assert_eq!(91, udp_datagram.data_length());
        assert_eq!(&[0xFF; 5], udp_datagram.payload());
        udp_datagram.set_udp_length(0x8).unwrap();
        assert_eq!(0x8, udp_datagram.udp_length());
        assert_eq!(0x20, udp_datagram.ipv6_payload_length());
        assert_eq!(86, udp_datagram.data_length());
        assert_eq!(&[0xFF; 0], udp_datagram.payload());
        udp_datagram.set_udp_length(0xE).unwrap();
        assert_eq!(0xE, udp_datagram.udp_length());
        assert_eq!(0x26, udp_datagram.ipv6_payload_length());
        assert_eq!(92, udp_datagram.data_length());
        assert_eq!(&[0xFF; 6], udp_datagram.payload());
    }

    #[test]
    fn set_udp_checksum() {
        let mut udp_datagram =
            DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(UDP, 0).unwrap();

        assert_eq!(0xABCD, udp_datagram.udp_checksum());
        udp_datagram.set_udp_checksum(0xFFDD);
        assert_eq!(0xFFDD, udp_datagram.udp_checksum());
    }

    #[test]
    fn update_udp_checksum() {
        let mut udp_datagram =
            DataBuffer::<_, Udp<NoPreviousHeader>>::parse_udp_alone(UDP, 0).unwrap();

        assert_eq!(0xABCD, udp_datagram.udp_checksum());
        udp_datagram.update_udp_checksum();
        assert_eq!(0xA858, udp_datagram.udp_checksum());
    }

    // Checks whether the header start offset is changed correctly if a lower layer changes its size
    #[test]
    fn set_ipv4_ihl() {
        let mut data = [0; 124];
        copy_into_slice(&mut data, &ETH_IPV4_UDP, 60);
        let ethernet = DataBuffer::<_, Eth>::parse_ethernet_layer(data, 60).unwrap();
        let ipv4 = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(ethernet, true).unwrap();

        let mut tcp_packet = DataBuffer::<_, Udp<Ipv4<Eth>>>::parse_udp_layer(ipv4, true).unwrap();

        let source_port = tcp_packet.udp_source_port();
        assert_eq!(38, tcp_packet.header_start_offset(Layer::Udp));
        tcp_packet.set_ipv4_ihl(15).unwrap();
        assert_eq!(74, tcp_packet.header_start_offset(Layer::Udp));
        assert_eq!(source_port, tcp_packet.udp_source_port());
        tcp_packet.set_ipv4_ihl(5).unwrap();
        assert_eq!(34, tcp_packet.header_start_offset(Layer::Udp));
        assert_eq!(source_port, tcp_packet.udp_source_port());
    }
}
