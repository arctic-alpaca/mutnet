//! IPV6 implementation and IPV6 specific errors.

pub use error::*;
pub use method_traits::*;

use crate::data_buffer::traits::HeaderMetadataExtraction;
use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderMetadata, HeaderMetadataMut, Layer,
};
use crate::data_buffer::{
    BufferIntoInner, DataBuffer, EthernetMarker, Ieee802_1QVlanMarker, Ipv6Marker, Payload,
    PayloadMut,
};
use crate::error::{LengthExceedsAvailableSpaceError, UnexpectedBufferEndError};
use crate::internal_utils::{check_and_calculate_data_length, header_start_offset_from_phi};
use crate::no_previous_header::NoPreviousHeader;

mod error;
mod method_traits;

#[cfg(all(feature = "remove_checksum", feature = "verify_ipv6", kani))]
mod verification;

/// IPv6 metadata.
///
/// Contains metadata about the IPv6 header in the parsed data buffer.
#[allow(private_bounds)]
#[derive(Eq, PartialEq, Hash, Copy, Clone, Debug)]
pub struct Ipv6<PHM>
where
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    header_start_offset: usize,
    /// Header and extensions
    header_length: usize,
    /// Offset of the next header field of the last extension from the header_min_size
    previous_header_metadata: PHM,
}

impl<PHM> Ipv6Marker for Ipv6<PHM> where PHM: HeaderMetadata + HeaderMetadataMut {}
impl<PHM> EthernetMarker for Ipv6<PHM> where PHM: HeaderMetadata + HeaderMetadataMut + EthernetMarker
{}
impl<PHM> Ieee802_1QVlanMarker for Ipv6<PHM> where
    PHM: HeaderMetadata + HeaderMetadataMut + Ieee802_1QVlanMarker
{
}

#[allow(private_bounds)]
impl<B, PHM> DataBuffer<B, Ipv6<PHM>>
where
    B: AsRef<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut + Copy,
{
    /// Parses `buf` and creates a new [`DataBuffer`] for an IPv6 layer with no previous layers.
    ///
    /// `headroom` indicates the amount of headroom in the provided `buf`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided data buffer is shorter than expected.
    /// - the version field is not six.
    #[inline]
    pub fn parse_ipv6_alone(
        buf: B,
        headroom: usize,
    ) -> Result<DataBuffer<B, Ipv6<NoPreviousHeader>>, ParseIpv6Error> {
        let lower_layer_data_buffer = DataBuffer::<B, NoPreviousHeader>::new(buf, headroom)?;
        DataBuffer::<B, Ipv6<NoPreviousHeader>>::parse_ipv6_layer(lower_layer_data_buffer)
    }

    /// Consumes the `lower_layer_data_buffer` and creates a new [`DataBuffer`] with an additional
    /// IPv6 layer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided data buffer is shorter than expected.
    /// - the version field is not six.
    #[inline]
    pub fn parse_ipv6_layer(
        lower_layer_data_buffer: impl HeaderMetadata
            + Payload
            + BufferIntoInner<B>
            + HeaderMetadataExtraction<PHM>,
    ) -> Result<DataBuffer<B, Ipv6<PHM>>, ParseIpv6Error> {
        let previous_header_metadata = lower_layer_data_buffer.extract_header_metadata();

        let header_and_payload_length = check_and_calculate_data_length::<ParseIpv6Error>(
            lower_layer_data_buffer.payload_length(),
            0,
            HEADER_MIN_LEN,
        )?;

        // Accessing the buffer once and doing some math is faster than accessing the buffer twice
        // to get version and payload length separately.
        let version_and_payload_length =
            u64::from_be_bytes(lower_layer_data_buffer.payload()[0..8].try_into().unwrap());
        if version_and_payload_length >> (VERSION_SHIFT + 7 * 8) != 0x6 {
            return Err(ParseIpv6Error::VersionHeaderValueNotSix);
        }

        let payload_length = usize::from((version_and_payload_length >> (2 * 8)) as u16);

        if payload_length > header_and_payload_length - HEADER_MIN_LEN {
            return Err(ParseIpv6Error::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: payload_length,
                    actual_length: header_and_payload_length - HEADER_MIN_LEN,
                },
            ));
        }

        let header_start_offset = header_start_offset_from_phi(previous_header_metadata);

        let mut result = DataBuffer {
            header_metadata: Ipv6 {
                header_start_offset,
                header_length: HEADER_MIN_LEN,
                previous_header_metadata: *previous_header_metadata,
            },
            buffer: lower_layer_data_buffer.buffer_into_inner(),
        };

        let data_length = header_start_offset + HEADER_MIN_LEN + payload_length;
        result.set_data_length(data_length, result.buffer.as_ref().len())?;

        Ok(result)
    }
}

impl<PHM> HeaderMetadata for Ipv6<PHM>
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
    fn data_length_internal(&self) -> usize {
        self.previous_header_metadata.data_length_internal()
    }
}

impl<PHM> HeaderMetadataMut for Ipv6<PHM>
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

impl<B, PHM> Payload for DataBuffer<B, Ipv6<PHM>>
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

impl<B, PHM> PayloadMut for DataBuffer<B, Ipv6<PHM>>
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

impl<B, HM> Ipv6Methods for DataBuffer<B, HM>
where
    B: AsRef<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + Ipv6Marker,
{
}

impl<B, HM> Ipv6MethodsMut for DataBuffer<B, HM>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + Ipv6Marker + Sized,
{
}

impl<B, HM> UpdateIpv6Length for DataBuffer<B, HM>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + Ipv6Marker + Sized,
{
}

#[cfg(test)]
mod tests {
    use crate::data_buffer::traits::{HeaderMetadata, Layer};
    use crate::data_buffer::{DataBuffer, Payload, PayloadMut};
    use crate::error::{LengthExceedsAvailableSpaceError, UnexpectedBufferEndError};
    use crate::ethernet::Eth;
    use crate::ipv6::{Ipv6, Ipv6Methods, Ipv6MethodsMut, ParseIpv6Error, SetPayloadLengthError};
    use crate::ipv6_extensions::Ipv6Extensions;
    use crate::no_previous_header::NoPreviousHeader;
    use crate::tcp::Tcp;
    use crate::typed_protocol_headers::InternetProtocolNumber;
    use crate::typed_protocol_headers::Ipv6ExtensionType;
    use crate::typed_protocol_headers::RoutingType;
    use core::net::Ipv6Addr;

    const ETH_IPV6_EXT_TCP: [u8; 104] = [
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
        0x32,
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
        InternetProtocolNumber::Tcp as u8,
        0, // Length
        0xCC,
        0xCC,
        0xCC,
        0xCC,
        0xCC,
        0xCC,
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
        0xDD,
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

    static IPV6_PACKET: [u8; 49] = [
        // Version, traffic class and flow label
        0x61,
        0x23,
        0xFF,
        0xFF,
        // Payload Length
        0x00,
        0x09,
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
        // Payload
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
    ];

    #[test]
    fn new() {
        assert!(DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0,).is_ok());
    }

    #[test]
    fn new_data_buffer_too_short() {
        // Checks payload length
        assert_eq!(
            Err(ParseIpv6Error::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 9,
                    actual_length: 8,
                }
            )),
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(
                &IPV6_PACKET[..IPV6_PACKET.len() - 1],
                0,
            )
        );

        // Checks min header length
        assert_eq!(
            Err(ParseIpv6Error::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 40,
                    actual_length: 39,
                }
            )),
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(&IPV6_PACKET[..39], 0)
        );
    }

    #[test]
    fn new_headroom_out_of_range() {
        assert_eq!(
            Err(ParseIpv6Error::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 500,
                    actual_length: 49,
                }
            )),
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 500,)
        );
    }

    #[test]
    fn new_wrong_version() {
        let mut data = IPV6_PACKET;
        data[0] = 0x51;
        assert_eq!(
            Err(ParseIpv6Error::VersionHeaderValueNotSix),
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(&data, 0,)
        );
    }

    #[test]
    fn new_payload_length_too_large() {
        let mut data = IPV6_PACKET;
        data[5] = 0xFF;
        assert_eq!(
            Err(ParseIpv6Error::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 255,
                    actual_length: 9,
                }
            )),
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(&data, 0,)
        );
    }

    #[test]
    fn ipv6_version() {
        let ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(6, ipv6_packet.ipv6_version());
    }

    #[test]
    fn ipv6_traffic_class() {
        let ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(0x12, ipv6_packet.ipv6_traffic_class());
    }

    #[test]
    fn ipv6_flow_label() {
        let ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(0x3FFFF, ipv6_packet.ipv6_flow_label());
    }

    #[test]
    fn ipv6_payload_length() {
        let ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(0x9, ipv6_packet.ipv6_payload_length());
    }

    #[test]
    fn ipv6_next_header() {
        let ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(
            InternetProtocolNumber::Tcp as u8,
            ipv6_packet.ipv6_next_header()
        );
    }

    #[test]
    fn ipv6_typed_next_header() {
        let ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(
            Ok(InternetProtocolNumber::Tcp),
            ipv6_packet.ipv6_typed_next_header()
        );
    }

    #[test]
    fn ipv6_hop_limit() {
        let ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(0xFF, ipv6_packet.ipv6_hop_limit());
    }

    #[test]
    fn ipv6_source() {
        let ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(
            Ipv6Addr::from([
                0xFF_u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF,
            ]),
            ipv6_packet.ipv6_source()
        );
    }

    #[test]
    fn ipv6_destination() {
        let ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(
            Ipv6Addr::from([
                0xFF_u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF,
            ]),
            ipv6_packet.ipv6_destination()
        );
    }

    #[test]
    fn payload() {
        let ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,],
            ipv6_packet.payload()
        );
    }

    #[test]
    fn payload_mut() {
        let mut ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(
            &mut [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,],
            ipv6_packet.payload_mut()
        );
    }
    #[test]
    fn payload_length() {
        let ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(9, ipv6_packet.payload_length());
    }

    #[test]
    fn set_ipv6_traffic_class() {
        let mut ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(0x12, ipv6_packet.ipv6_traffic_class());
        ipv6_packet.set_ipv6_traffic_class(0xFF);
        assert_eq!(0xFF, ipv6_packet.ipv6_traffic_class());
        assert_eq!(6, ipv6_packet.ipv6_version());
    }

    #[test]
    fn set_ipv6_flow_label() {
        let mut ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(0x3FFFF, ipv6_packet.ipv6_flow_label());
        ipv6_packet.set_ipv6_flow_label(0xF1111);
        assert_eq!(0xF1111, ipv6_packet.ipv6_flow_label());
        assert_eq!(6, ipv6_packet.ipv6_version());
    }

    #[test]
    fn set_ipv6_payload_length() {
        let mut ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(9, ipv6_packet.payload_length());
        assert_eq!(Ok(()), ipv6_packet.set_ipv6_payload_length(8));
        assert_eq!(8, ipv6_packet.payload_length());

        assert_eq!(Ok(()), ipv6_packet.set_ipv6_payload_length(9));
        assert_eq!(9, ipv6_packet.payload_length());

        assert_eq!(Ok(()), ipv6_packet.set_ipv6_payload_length(0));
        assert_eq!(0, ipv6_packet.payload_length());

        assert_eq!(
            Err(SetPayloadLengthError::LengthExceedsAvailableSpace(
                LengthExceedsAvailableSpaceError {
                    required_space: 50,
                    available_space: 49,
                }
            )),
            ipv6_packet.set_ipv6_payload_length(10)
        );
    }

    #[test]
    fn set_ipv6_payload_length_ipv6_ext_tcp() {
        let mut tcp = DataBuffer::<_, Tcp<Ipv6Extensions<Ipv6<Eth>, 10>>>::parse_tcp_layer(
            DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, 10>>::parse_ipv6_extensions_layer(
                DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                    DataBuffer::<_, Eth>::parse_ethernet_layer(ETH_IPV6_EXT_TCP, 0).unwrap(),
                )
                .unwrap(),
                Ipv6ExtensionType::HopByHop,
            )
            .unwrap()
            .0,
            true,
        )
        .unwrap();
        assert_eq!(50, tcp.ipv6_payload_length());
        assert_eq!(24, tcp.header_length(Layer::Ipv6Ext));
        assert_eq!(20, tcp.header_length(Layer::Tcp));
        assert_eq!(6, tcp.payload_length());
        assert_eq!(Ok(()), tcp.set_ipv6_payload_length(48));
        assert_eq!(48, tcp.ipv6_payload_length());
        assert_eq!(24, tcp.header_length(Layer::Ipv6Ext));
        assert_eq!(20, tcp.header_length(Layer::Tcp));
        assert_eq!(4, tcp.payload_length());

        assert_eq!(
            Err(SetPayloadLengthError::CannotCutUpperLayerHeader),
            tcp.set_ipv6_payload_length(43)
        );
    }

    #[test]
    fn set_ipv6_payload_length_ipv6_ext() {
        let mut ipv6_ext =
            DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, 10>>::parse_ipv6_extensions_layer(
                DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                    DataBuffer::<_, Eth>::parse_ethernet_layer(ETH_IPV6_EXT_TCP, 0).unwrap(),
                )
                .unwrap(),
                Ipv6ExtensionType::HopByHop,
            )
            .unwrap()
            .0;
        assert_eq!(50, ipv6_ext.ipv6_payload_length());
        assert_eq!(24, ipv6_ext.header_length(Layer::Ipv6Ext));
        assert_eq!(Ok(()), ipv6_ext.set_ipv6_payload_length(24));
        assert_eq!(24, ipv6_ext.ipv6_payload_length());
        assert_eq!(24, ipv6_ext.header_length(Layer::Ipv6Ext));

        assert_eq!(
            Err(SetPayloadLengthError::CannotCutUpperLayerHeader),
            ipv6_ext.set_ipv6_payload_length(23)
        );
    }

    #[test]
    fn set_ipv6_next_header() {
        let mut ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(
            Ok(InternetProtocolNumber::Tcp),
            ipv6_packet.ipv6_typed_next_header()
        );
        ipv6_packet.set_ipv6_next_header(InternetProtocolNumber::Udp as u8);
        assert_eq!(
            Ok(InternetProtocolNumber::Udp),
            ipv6_packet.ipv6_typed_next_header()
        );
    }

    #[test]
    fn set_ipv6_hop_limit() {
        let mut ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(0xFF, ipv6_packet.ipv6_hop_limit());
        ipv6_packet.set_ipv6_hop_limit(0x0);
        assert_eq!(0x0, ipv6_packet.ipv6_hop_limit());
    }

    #[test]
    fn set_ipv6_source() {
        let mut ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(Ipv6Addr::from([0xFF; 16]), ipv6_packet.ipv6_source());
        ipv6_packet.set_ipv6_source(Ipv6Addr::from([0x00; 16]));
        assert_eq!(Ipv6Addr::from([0x00; 16]), ipv6_packet.ipv6_source());
    }

    #[test]
    fn set_ipv6_destination() {
        let mut ipv6_packet =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_PACKET, 0).unwrap();

        assert_eq!(Ipv6Addr::from([0xFF; 16]), ipv6_packet.ipv6_destination());
        ipv6_packet.set_ipv6_destination(Ipv6Addr::from([0x00; 16]));
        assert_eq!(Ipv6Addr::from([0x00; 16]), ipv6_packet.ipv6_destination());
    }
}
