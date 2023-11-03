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
use crate::ipv4::{Ipv4, UpdateIpv4Length};
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
    /// # Note
    ///
    /// Inconsistencies between the IP payload length allocated for the UDP datagram and the UDP
    /// length are permissible as long as the indicated IP payload length is larger than the UDP
    /// length.
    /// https://datatracker.ietf.org/doc/html/rfc768
    /// https://datatracker.ietf.org/doc/html/draft-ietf-tsvwg-udp-options-01#section-9
    ///
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
            lower_layer_data_buffer.payload()[LENGTH]
                .try_into()
                .unwrap(),
        ));

        if length_header < HEADER_MIN_LEN {
            return Err(ParseUdpError::LengthHeaderTooSmall { length_header });
        }

        if length_header > data_length {
            return Err(ParseUdpError::LengthHeaderTooLarge {
                data_length,
                length_header,
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
    fn pseudoheader_checksum(&self) -> u64 {
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
{
    #[inline]
    fn pseudoheader_checksum(&self) -> u64 {
        pseudoheader_checksum_ipv4_internal(self, UDP)
    }
}

impl<B, PHI> TcpUdpChecksum for DataBuffer<B, Udp<Ipv6<PHI>>>
where
    B: AsRef<[u8]>,
    PHI: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn pseudoheader_checksum(&self) -> u64 {
        pseudoheader_checksum_ipv6_internal(self, UDP)
    }
}

impl<B, PHI, const MAX_EXTENSIONS: usize> TcpUdpChecksum
    for DataBuffer<B, Udp<Ipv6Extensions<PHI, MAX_EXTENSIONS>>>
where
    B: AsRef<[u8]>,
    PHI: HeaderInformation + HeaderInformationMut + Ipv6Marker,
{
    #[inline]
    fn pseudoheader_checksum(&self) -> u64 {
        pseudoheader_checksum_ipv6_internal(self, UDP)
    }
}

impl<PHI> HeaderInformation for Udp<PHI>
where
    PHI: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn headroom_internal(&self) -> usize {
        self.previous_header_information.headroom_internal()
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
    fn extensions_array(&self) -> &[Ipv6ExtensionMetadata; MAX_EXTENSIONS] {
        self.previous_header_information.extensions_array()
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
    fn extensions_array_mut(&mut self) -> &mut [Ipv6ExtensionMetadata; MAX_EXTENSIONS] {
        self.previous_header_information.extensions_array_mut()
    }
}

impl<PHI> HeaderInformationMut for Udp<PHI>
where
    PHI: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn headroom_internal_mut(&mut self) -> &mut usize {
        self.previous_header_information.headroom_internal_mut()
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
    DataBuffer<B, Udp<PHI>>: TcpUdpChecksum,
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

impl<B, PHI> PayloadMut for DataBuffer<B, Udp<PHI>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    PHI: HeaderInformation + HeaderInformationMut,
    DataBuffer<B, Udp<PHI>>: TcpUdpChecksum,
{
    #[inline]
    fn payload_mut(&mut self) -> &mut [u8] {
        let payload_start = self.header_length(LAYER);
        let payload_end = usize::from(self.udp_length());
        &mut self.data_buffer_starting_at_header_mut(LAYER)[payload_start..payload_end]
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

#[cfg(test)]
mod tests {
    use crate::data_buffer::{DataBuffer, HeaderInformation, Layer, Payload, PayloadMut};
    use crate::error::{UnexpectedBufferEndError, WrongChecksumError};
    use crate::ethernet::Eth;
    use crate::internet_protocol::InternetProtocolNumber;
    use crate::ipv4::{Ipv4, Ipv4MethodsMut};
    use crate::ipv6::{Ipv6, Ipv6Methods, Ipv6MethodsMut};
    use crate::ipv6_extensions::{Ipv6Extension, Ipv6Extensions, RoutingType};
    use crate::no_previous_header::NoPreviousHeaderInformation;
    use crate::test_utils::copy_into_slice;
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
        Ipv6Extension::HopByHop as u8,
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
        Ipv6Extension::Routing as u8,
        0, // Length
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        Ipv6Extension::DestinationOptions as u8,
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
            DataBuffer::<_, Udp<Ipv6Extensions<Ipv6<Eth>, 10>>>::new_from_lower(
                DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, 10>>::new_from_lower(
                    DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                        DataBuffer::<_, Eth>::new(ETH_IPV6_EXT_UDP, 0).unwrap(),
                    )
                    .unwrap(),
                    Ipv6Extension::Routing,
                )
                .unwrap()
                .0,
                true,
            )
            .is_ok()
        );

        assert!(
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(UDP, 0).is_ok()
        );
    }

    #[test]
    fn new_data_buffer_too_short() {
        assert!(
            DataBuffer::<_, Udp<Ipv6Extensions<Ipv6<Eth>, 10>>>::new_from_lower(
                DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, 10>>::new_from_lower(
                    DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                        DataBuffer::<_, Eth>::new(ETH_IPV6_EXT_UDP, 0).unwrap(),
                    )
                    .unwrap(),
                    Ipv6Extension::Routing,
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
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(&UDP[..7], 0)
        );
    }

    #[test]
    fn new_ipv6_payload_shorter_than_udp_length() {
        let mut ipv6 = DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, 10>>::new_from_lower(
            DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                DataBuffer::<_, Eth>::new(ETH_IPV6_EXT_UDP, 0).unwrap(),
            )
            .unwrap(),
            Ipv6Extension::Routing,
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
            DataBuffer::<_, Udp<_>>::new_from_lower(ipv6.clone(), false)
        );
        ipv6.set_ipv6_payload_length(32).unwrap();
        assert_eq!(
            Err(ParseUdpError::LengthHeaderTooLarge {
                data_length: 8,
                length_header: 12,
            }),
            DataBuffer::<_, Udp<_>>::new_from_lower(ipv6.clone(), false)
        );
    }

    #[test]
    fn new_invalid_length_header() {
        let mut data = UDP;
        data[5] = 7;
        assert_eq!(
            Err(ParseUdpError::LengthHeaderTooSmall { length_header: 7 }),
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(data, 0,)
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
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(UDP, 500,)
        );
    }

    #[test]
    fn new_payload_length_too_large() {
        let mut data = UDP;
        data[4] = 0xFF;
        assert_eq!(
            Err(ParseUdpError::LengthHeaderTooLarge {
                data_length: 14,
                length_header: 65292
            }),
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(data, 0,)
        );
    }

    #[test]
    fn new_invalid_checksum() {
        let mut ipv6 = DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, 10>>::new_from_lower(
            DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                DataBuffer::<_, Eth>::new(ETH_IPV6_EXT_UDP, 0).unwrap(),
            )
            .unwrap(),
            Ipv6Extension::Routing,
        )
        .unwrap()
        .0;
        ipv6.set_ipv6_destination([0; 16]);
        assert_eq!(
            Err(ParseUdpError::WrongChecksum(WrongChecksumError {
                calculated_checksum: 65501
            })),
            DataBuffer::<_, Udp<_>>::new_from_lower(ipv6.clone(), true)
        );
    }

    #[test]
    fn udp_source_port() {
        let udp_datagram =
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(UDP, 0)
                .unwrap();

        assert_eq!(0x1234, udp_datagram.udp_source_port());
    }

    #[test]
    fn udp_destination_port() {
        let udp_datagram =
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(UDP, 0)
                .unwrap();

        assert_eq!(0x4567, udp_datagram.udp_destination_port());
    }

    #[test]
    fn udp_length() {
        let udp_datagram =
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(UDP, 0)
                .unwrap();

        assert_eq!(0xC, udp_datagram.udp_length());
    }

    #[test]
    fn udp_checksum() {
        let udp_datagram =
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(UDP, 0)
                .unwrap();

        assert_eq!(0xABCD, udp_datagram.udp_checksum());
    }

    #[test]
    fn udp_calculate_checksum() {
        let udp_datagram =
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(UDP, 0)
                .unwrap();

        assert_eq!(0xFC8A, udp_datagram.udp_calculate_checksum());
    }

    #[test]
    fn payload() {
        let udp_datagram =
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(UDP, 0)
                .unwrap();

        assert_eq!(&[0xFF; 4], udp_datagram.payload());
    }

    #[test]
    fn payload_mut() {
        let mut udp_datagram =
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(UDP, 0)
                .unwrap();

        assert_eq!(&[0xFF; 4], udp_datagram.payload_mut());
    }

    #[test]
    fn payload_length() {
        let udp_datagram =
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(UDP, 0)
                .unwrap();

        assert_eq!(4, udp_datagram.payload_length());
    }

    #[test]
    fn set_udp_source_port() {
        let mut udp_datagram =
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(UDP, 0)
                .unwrap();

        assert_eq!(0x1234, udp_datagram.udp_source_port());
        udp_datagram.set_udp_source_port(0xFFDD);
        assert_eq!(0xFFDD, udp_datagram.udp_source_port());
    }

    #[test]
    fn set_udp_destination_port() {
        let mut udp_datagram =
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(UDP, 0)
                .unwrap();

        assert_eq!(0x4567, udp_datagram.udp_destination_port());
        udp_datagram.set_udp_destination_port(0xFFDD);
        assert_eq!(0xFFDD, udp_datagram.udp_destination_port());
    }

    #[test]
    fn set_udp_length() {
        let mut udp_datagram = DataBuffer::<_, Udp<Ipv6Extensions<Ipv6<Eth>, 10>>>::new_from_lower(
            DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, 10>>::new_from_lower(
                DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                    DataBuffer::<_, Eth>::new(ETH_IPV6_EXT_UDP, 0).unwrap(),
                )
                .unwrap(),
                Ipv6Extension::Routing,
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
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(UDP, 0)
                .unwrap();

        assert_eq!(0xABCD, udp_datagram.udp_checksum());
        udp_datagram.set_udp_checksum(0xFFDD);
        assert_eq!(0xFFDD, udp_datagram.udp_checksum());
    }

    #[test]
    fn update_udp_checksum() {
        let mut udp_datagram =
            DataBuffer::<_, Udp<NoPreviousHeaderInformation>>::new_without_checksum(UDP, 0)
                .unwrap();

        assert_eq!(0xABCD, udp_datagram.udp_checksum());
        udp_datagram.update_udp_checksum();
        assert_eq!(0xA858, udp_datagram.udp_checksum());
    }

    // Checks whether the header start offset is changed correctly if a lower layer changes its size
    #[test]
    fn set_ipv4_ihl() {
        let mut data = [0; 124];
        copy_into_slice(&mut data, &ETH_IPV4_UDP, 60);
        let ethernet = DataBuffer::<_, Eth>::new(data, 60).unwrap();
        let ipv4 = DataBuffer::<_, Ipv4<Eth>>::new_from_lower(ethernet, true).unwrap();

        let mut tcp_packet = DataBuffer::<_, Udp<Ipv4<Eth>>>::new_from_lower(ipv4, true).unwrap();

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
