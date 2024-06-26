//! IPV4 implementation and IPV4 specific errors.

pub use error::*;
pub use method_traits::*;

use crate::data_buffer::traits::HeaderMetadataExtraction;
use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderMetadata, HeaderMetadataMut, Layer,
};
use crate::data_buffer::{
    BufferIntoInner, DataBuffer, EthernetMarker, Ieee802_1QVlanMarker, Ipv4Marker, Payload,
    PayloadMut,
};
use crate::error::{InvalidChecksumError, LengthExceedsAvailableSpaceError};
use crate::internal_utils::{check_and_calculate_data_length, header_start_offset_from_phi};
use crate::no_previous_header::NoPreviousHeader;

mod error;
mod method_traits;

#[cfg(all(feature = "remove_checksum", feature = "verify_ipv4", kani))]
mod verification;

/// IPv4 metadata.
///
/// Contains metadata about the IPv4 header in the parsed data buffer.
#[allow(private_bounds)]
#[derive(Eq, PartialEq, Hash, Copy, Clone, Debug)]
pub struct Ipv4<PHM>
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

impl<PHM> Ipv4Marker for Ipv4<PHM> where PHM: HeaderMetadata + HeaderMetadataMut {}
impl<PHM> EthernetMarker for Ipv4<PHM> where PHM: HeaderMetadata + HeaderMetadataMut + EthernetMarker
{}
impl<PHM> Ieee802_1QVlanMarker for Ipv4<PHM> where
    PHM: HeaderMetadata + HeaderMetadataMut + Ieee802_1QVlanMarker
{
}

#[allow(private_bounds)]
impl<B, PHM> DataBuffer<B, Ipv4<PHM>>
where
    B: AsRef<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut + Copy,
{
    /// Parses `buf` and creates a new [`DataBuffer`] for an IPv4 layer with no previous layers.
    ///
    /// `headroom` indicates the amount of headroom in the provided `buf`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided data buffer is shorter than expected.
    /// - the version field is not four.
    /// - the IHL field or total length field values are invalid.
    /// - if `check_ipv4_checksum` is true and the checksum is invalid.
    #[inline]
    pub fn parse_ipv4_alone(
        buf: B,
        headroom: usize,
        check_ipv4_checksum: bool,
    ) -> Result<DataBuffer<B, Ipv4<NoPreviousHeader>>, ParseIpv4Error> {
        let lower_layer_data_buffer = DataBuffer::<B, NoPreviousHeader>::new(buf, headroom)?;
        DataBuffer::<B, Ipv4<NoPreviousHeader>>::parse_ipv4_layer(
            lower_layer_data_buffer,
            check_ipv4_checksum,
        )
    }

    /// Consumes the `lower_layer_data_buffer` and creates a new [`DataBuffer`] with an additional
    /// IPv4 layer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided data buffer is shorter than expected.
    /// - the version field is not four.
    /// - the IHL field or total length field values are invalid.
    /// - if `check_ipv4_checksum` is true and the checksum is invalid.
    #[inline]
    pub fn parse_ipv4_layer(
        lower_layer_data_buffer: impl HeaderMetadata
            + Payload
            + BufferIntoInner<B>
            + HeaderMetadataExtraction<PHM>,
        check_ipv4_checksum: bool,
    ) -> Result<DataBuffer<B, Ipv4<PHM>>, ParseIpv4Error> {
        let previous_header_metadata = lower_layer_data_buffer.extract_header_metadata();

        let header_and_payload_length = check_and_calculate_data_length::<ParseIpv4Error>(
            lower_layer_data_buffer.payload_length(),
            0,
            HEADER_MIN_LEN,
        )?;

        // Only accessing the buffer once, then doing math like in the IPv6 new method does not
        // lead to improvements in benchmarks. The compiler is probably optimizing this already.

        let first_byte = lower_layer_data_buffer.payload()[0];
        if first_byte >> VERSION_SHIFT != 0x4 {
            return Err(ParseIpv4Error::VersionHeaderValueNotFour);
        }

        let ihl_header = usize::from(first_byte & IHL_MASK);

        if ihl_header < *IHL_RANGE.start() {
            return Err(ParseIpv4Error::IhlHeaderValueTooSmall { ihl: ihl_header });
        }

        let ihl_header_in_bytes = ihl_header * 4;

        let total_length_header = usize::from(u16::from_be_bytes(
            lower_layer_data_buffer.payload()[TOTAL_LENGTH]
                .try_into()
                .unwrap(),
        ));

        if total_length_header < ihl_header_in_bytes {
            return Err(
                ParseIpv4Error::TotalLengthHeaderValueSmallerThanIhlHeaderValue {
                    total_length_header,
                    ihl_header_in_bytes,
                },
            );
        }

        if total_length_header > header_and_payload_length {
            return Err(ParseIpv4Error::PacketShorterThanTotalLengthHeaderValue {
                total_length_header,
                actual_packet_length: header_and_payload_length,
            });
        }

        let header_start_offset = header_start_offset_from_phi(previous_header_metadata);

        let mut result = DataBuffer {
            header_metadata: Ipv4 {
                header_start_offset,
                header_length: ihl_header_in_bytes,
                previous_header_metadata: *previous_header_metadata,
            },
            buffer: lower_layer_data_buffer.buffer_into_inner(),
        };

        let data_length = header_start_offset + total_length_header;
        result.set_data_length(data_length, result.buffer.as_ref().len())?;

        if check_ipv4_checksum {
            let checksum = result.ipv4_calculate_checksum();
            if checksum != 0 {
                return Err(ParseIpv4Error::InvalidChecksum(InvalidChecksumError {
                    calculated_checksum: checksum,
                }));
            }
        }
        Ok(result)
    }
}

impl<PHM> HeaderMetadata for Ipv4<PHM>
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

impl<PHM> HeaderMetadataMut for Ipv4<PHM>
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

impl<B, PHM> Payload for DataBuffer<B, Ipv4<PHM>>
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

impl<B, PHM> PayloadMut for DataBuffer<B, Ipv4<PHM>>
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

impl<B, HM> Ipv4Methods for DataBuffer<B, HM>
where
    B: AsRef<[u8]>,
    HM: Ipv4Marker + HeaderMetadata + HeaderMetadataMut,
{
}

impl<B, HM> Ipv4MethodsMut for DataBuffer<B, HM>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + Ipv4Marker + Sized,
{
}

impl<B, HM> UpdateIpv4Length for DataBuffer<B, HM>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + Ipv4Marker + Sized,
{
}

#[cfg(test)]
mod tests {
    use crate::data_buffer::{DataBuffer, Payload, PayloadMut};
    use crate::error::{
        InvalidChecksumError, LengthExceedsAvailableSpaceError, NotEnoughHeadroomError,
        UnexpectedBufferEndError,
    };
    use crate::ethernet::Eth;
    use crate::ipv4::{
        Ipv4, Ipv4Methods, Ipv4MethodsMut, ParseIpv4Error, SetIhlError, SetTotalLengthError,
    };
    use crate::no_previous_header::NoPreviousHeader;
    use crate::tcp::Tcp;
    use crate::test_utils::copy_into_slice;
    use crate::typed_protocol_headers::InternetProtocolNumber;
    use crate::typed_protocol_headers::{Dscp, Ecn};
    use core::net::Ipv4Addr;

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

    static IPV4_PACKET: [u8; 30] = [
        // Version & IHL
        0x46,
        // DSCP & ECN
        0b0010_1000,
        // Total length
        0x00,
        0x19,
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
        0x7A,
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
        0xFF,
        // not used
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
    ];

    #[test]
    fn new() {
        assert!(
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true).is_ok()
        );
    }

    #[test]
    fn new_data_buffer_too_short() {
        assert_eq!(
            Err(ParseIpv4Error::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 20,
                    actual_length: 19
                }
            )),
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(&IPV4_PACKET[..19], 0, true)
        );
    }

    #[test]
    fn new_headroom_out_of_range() {
        assert_eq!(
            Err(ParseIpv4Error::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: IPV4_PACKET.len() + 1,
                    actual_length: IPV4_PACKET.len(),
                }
            )),
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(
                &IPV4_PACKET,
                IPV4_PACKET.len() + 1,
                true
            )
        );
    }

    #[test]
    fn new_wrong_version() {
        let mut data = IPV4_PACKET;
        data[0] = 0x10;
        assert_eq!(
            Err(ParseIpv4Error::VersionHeaderValueNotFour),
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(&data, 0, true)
        );
    }

    #[test]
    fn new_ihl_too_low() {
        let mut data = IPV4_PACKET;
        data[0] = 0x44;
        assert_eq!(
            Err(ParseIpv4Error::IhlHeaderValueTooSmall { ihl: 4 }),
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(&data, 0, true)
        );
    }

    #[test]
    fn new_total_length_less_than_ihl() {
        let mut data = IPV4_PACKET;
        data[3] = 0x17;
        assert_eq!(
            Err(
                ParseIpv4Error::TotalLengthHeaderValueSmallerThanIhlHeaderValue {
                    total_length_header: 23,
                    ihl_header_in_bytes: 24
                }
            ),
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(&data, 0, true)
        );
    }

    #[test]
    fn new_total_length_more_than_buffer_length() {
        let mut data = IPV4_PACKET;
        data[3] = data.len() as u8 + 1;
        assert_eq!(
            Err(ParseIpv4Error::PacketShorterThanTotalLengthHeaderValue {
                total_length_header: data.len() + 1,
                actual_packet_length: data.len(),
            }),
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(&data, 0, true)
        );
    }

    #[test]
    fn new_wrong_checksum() {
        let mut data = IPV4_PACKET;
        data[4] = 0x0;
        assert_eq!(
            Err(ParseIpv4Error::InvalidChecksum(InvalidChecksumError {
                calculated_checksum: 4608
            })),
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(&data, 0, true)
        );
        assert!(DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(&data, 0, false).is_ok());
    }

    #[test]
    fn ipv4_version() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(4, ipv4_packet.ipv4_version());
    }

    #[test]
    fn ipv4_ihl() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(6, ipv4_packet.ipv4_ihl());
    }

    #[test]
    fn ipv4_dscp() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(0b0000_1010, ipv4_packet.ipv4_dscp());
    }

    #[test]
    fn ipv4_typed_dscp() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(Ok(Dscp::Af11), ipv4_packet.ipv4_typed_dscp());
    }

    #[test]
    fn ipv4_ecn() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(0, ipv4_packet.ipv4_ecn());
    }

    #[test]
    fn ipv4_typed_ecn() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(Ok(Ecn::NotEct), ipv4_packet.ipv4_typed_ecn());
    }

    #[test]
    fn ipv4_total_length() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(
            u16::from_be_bytes([0x00, 0x19,]),
            ipv4_packet.ipv4_total_length()
        );
    }

    #[test]
    fn ipv4_identification() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(
            u16::from_be_bytes([0x12, 0x34,]),
            ipv4_packet.ipv4_identification()
        );
    }

    #[test]
    fn ipv4_flags() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(0b000_0101, ipv4_packet.ipv4_flags());
    }

    #[test]
    fn ipv4_evil_flag() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert!(ipv4_packet.ipv4_evil_flag());
    }

    #[test]
    fn ipv4_dont_fragment_flag() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert!(!ipv4_packet.ipv4_dont_fragment_flag());
    }

    #[test]
    fn ipv4_more_fragments_flag() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert!(ipv4_packet.ipv4_more_fragments_flag());
    }

    #[test]
    fn ipv4_fragment_offset() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(3, ipv4_packet.ipv4_fragment_offset());
    }

    #[test]
    fn ipv4_time_to_live() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(1, ipv4_packet.ipv4_time_to_live());
    }

    #[test]
    fn ipv4_protocol() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(6, ipv4_packet.ipv4_protocol());
    }

    #[test]
    fn ipv4_typed_protocol() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(
            Ok(InternetProtocolNumber::Tcp),
            ipv4_packet.ipv4_typed_protocol()
        );
    }

    #[test]
    fn ipv4_header_checksum() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(
            u16::from_be_bytes([0x06, 0x7A,]),
            ipv4_packet.ipv4_header_checksum()
        );
    }

    #[test]
    fn ipv4_source() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(
            Ipv4Addr::from([0x7f, 0x00, 0x00, 0x1,]),
            ipv4_packet.ipv4_source()
        );
    }

    #[test]
    fn ipv4_destination() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(
            Ipv4Addr::from([0x7f, 0x00, 0x00, 0x1,]),
            ipv4_packet.ipv4_destination()
        );
    }

    #[test]
    fn ipv4_options() {
        // Options
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(&[0x02, 0x04, 0xFF, 0xFF], ipv4_packet.ipv4_options());

        // No options
        let mut data = IPV4_PACKET;
        data[0] = 0x45;
        data[10] = 0x09;
        data[11] = 0x7E;

        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(data, 0, true).unwrap();
        assert_eq!(&[0; 0], ipv4_packet.ipv4_options());
    }

    #[test]
    fn payload() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(&[0xFF], ipv4_packet.payload());
    }

    #[test]
    fn payload_mut() {
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(&[0xFF], ipv4_packet.payload_mut());
    }

    #[test]
    fn ipv4_payload_length() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(1, ipv4_packet.ipv4_payload_length());
    }

    #[test]
    fn payload_length() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(1, ipv4_packet.payload_length());
    }

    #[test]
    fn ipv4_calculate_checksum() {
        let ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();
        assert_eq!(0, ipv4_packet.ipv4_calculate_checksum());
    }

    #[test]
    fn set_ipv4_ihl() {
        let mut data = [0xFF_u8; 56];
        copy_into_slice(&mut data, &IPV4_PACKET, 4);
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(&mut data, 4, true).unwrap();
        assert_eq!(Ok(()), ipv4_packet.set_ipv4_ihl(7));
        assert_eq!(
            Err(SetIhlError::NotEnoughHeadroom(NotEnoughHeadroomError {
                required: 32,
                available: 0,
            })),
            ipv4_packet.set_ipv4_ihl(15)
        );

        assert_eq!(
            Err(SetIhlError::InvalidIhl { ihl: 16 }),
            ipv4_packet.set_ipv4_ihl(16)
        );
        assert_eq!(
            Err(SetIhlError::InvalidIhl { ihl: 1 }),
            ipv4_packet.set_ipv4_ihl(1)
        );
    }

    #[test]
    fn set_ipv4_dscp() {
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();

        assert_eq!(0b0000_1010, ipv4_packet.ipv4_dscp());
        ipv4_packet.set_ipv4_dscp(Dscp::Cs4);
        assert_eq!(Dscp::Cs4 as u8, ipv4_packet.ipv4_dscp());
    }

    #[test]
    fn set_ipv4_ecn() {
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();

        assert_eq!(0, ipv4_packet.ipv4_ecn());
        ipv4_packet.set_ipv4_ecn(Ecn::Ect0);
        assert_eq!(Ecn::Ect0 as u8, ipv4_packet.ipv4_ecn());
        assert_eq!(0b0000_1010, ipv4_packet.ipv4_dscp());
    }

    #[test]
    fn set_ipv4_total_length() {
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();

        assert_eq!(0x19, ipv4_packet.ipv4_total_length());
        ipv4_packet.set_ipv4_total_length(0x18).unwrap();
        assert_eq!(0x18, ipv4_packet.ipv4_total_length());
        ipv4_packet.set_ipv4_total_length(0x1E).unwrap();
        assert_eq!(0x1E, ipv4_packet.ipv4_total_length());
        assert_eq!(
            Err(SetTotalLengthError::LengthExceedsAvailableSpace(
                LengthExceedsAvailableSpaceError {
                    required_space: IPV4_PACKET.len() + 1,
                    available_space: IPV4_PACKET.len()
                }
            )),
            ipv4_packet.set_ipv4_total_length(IPV4_PACKET.len() as u16 + 1)
        );
        assert_eq!(
            Err(SetTotalLengthError::LengthExceedsAvailableSpace(
                LengthExceedsAvailableSpaceError {
                    required_space: 0x3000,
                    available_space: IPV4_PACKET.len()
                }
            )),
            ipv4_packet.set_ipv4_total_length(0x3000)
        );
        assert_eq!(
            Err(SetTotalLengthError::SmallerThanIhl),
            ipv4_packet.set_ipv4_total_length(23)
        );
    }

    #[test]
    fn set_ipv4_total_length_with_tcp() {
        let mut tcp_packet = DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(ETH_IPV4_TCP, 0).unwrap(),
                true,
            )
            .unwrap(),
            true,
        )
        .unwrap();

        assert_eq!(0x32, tcp_packet.ipv4_total_length());
        assert_eq!(6, tcp_packet.payload_length());
        tcp_packet.set_ipv4_total_length(0x30).unwrap();
        assert_eq!(0x30, tcp_packet.ipv4_total_length());
        assert_eq!(4, tcp_packet.payload_length());

        assert_eq!(
            Err(SetTotalLengthError::CannotCutUpperLayerHeader),
            tcp_packet.set_ipv4_total_length(0x20)
        );
    }

    #[test]
    fn set_ipv4_identification() {
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();

        assert_eq!(0x1234, ipv4_packet.ipv4_identification());
        ipv4_packet.set_ipv4_identification(0x1030);
        assert_eq!(0x1030, ipv4_packet.ipv4_identification());
    }

    #[test]
    fn set_ipv4_flags() {
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();

        assert_eq!(0b000_0101, ipv4_packet.ipv4_flags());
        ipv4_packet.set_ipv4_flags(0b111_1010);
        assert_eq!(0b000_0010, ipv4_packet.ipv4_flags());
    }

    #[test]
    fn set_ipv4_evil_flag() {
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();

        assert!(ipv4_packet.ipv4_evil_flag());
        ipv4_packet.set_ipv4_evil_flag(false);
        assert!(!ipv4_packet.ipv4_evil_flag());
    }

    #[test]
    fn set_ipv4_dont_fragment_flag() {
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();

        assert!(!ipv4_packet.ipv4_dont_fragment_flag());
        ipv4_packet.set_ipv4_dont_fragment_flag(true);
        assert!(ipv4_packet.ipv4_dont_fragment_flag());
    }

    #[test]
    fn set_ipv4_more_fragments_flag() {
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();

        assert!(ipv4_packet.ipv4_more_fragments_flag());
        ipv4_packet.set_ipv4_more_fragments_flag(false);
        assert!(!ipv4_packet.ipv4_more_fragments_flag());
    }

    #[test]
    fn set_ipv4_fragment_offset() {
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();

        assert_eq!(3, ipv4_packet.ipv4_fragment_offset());
        ipv4_packet.set_ipv4_fragment_offset(0b0001_1111_1111_1111);
        assert_eq!(0b0001_1111_1111_1111, ipv4_packet.ipv4_fragment_offset());
        assert_eq!(0b000_0000, ipv4_packet.ipv4_flags());
    }

    #[test]
    fn set_ipv4_time_to_live() {
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();

        assert_eq!(0x1, ipv4_packet.ipv4_time_to_live());
        ipv4_packet.set_ipv4_time_to_live(0x3);
        assert_eq!(0x3, ipv4_packet.ipv4_time_to_live());
    }

    #[test]
    fn set_ipv4_protocol() {
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();

        assert_eq!(0x6, ipv4_packet.ipv4_protocol());
        ipv4_packet.set_ipv4_protocol(InternetProtocolNumber::Adfl as u8);
        assert_eq!(68, ipv4_packet.ipv4_protocol());
    }

    #[test]
    fn set_ipv4_source() {
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();

        assert_eq!(
            Ipv4Addr::from([0x7f, 0x00, 0x00, 0x1]),
            ipv4_packet.ipv4_source()
        );
        ipv4_packet.set_ipv4_source(Ipv4Addr::from([0x0f, 0x01, 0x01, 0x2]));
        assert_eq!(
            Ipv4Addr::from([0x0f, 0x01, 0x01, 0x2]),
            ipv4_packet.ipv4_source()
        );
    }

    #[test]
    fn set_ipv4_destination() {
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();

        assert_eq!(
            Ipv4Addr::from([0x7f, 0x00, 0x00, 0x1]),
            ipv4_packet.ipv4_destination()
        );
        ipv4_packet.set_ipv4_destination(Ipv4Addr::from([0x0f, 0x01, 0x01, 0x2]));
        assert_eq!(
            Ipv4Addr::from([0x0f, 0x01, 0x01, 0x2]),
            ipv4_packet.ipv4_destination()
        );
    }

    #[test]
    fn update_ipv4_header_checksum() {
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();

        assert_eq!(0x067A, ipv4_packet.ipv4_header_checksum());
        ipv4_packet.set_ipv4_destination(Ipv4Addr::from([0xFF; 4]));
        ipv4_packet.update_ipv4_header_checksum();
        assert_eq!(34171, ipv4_packet.ipv4_header_checksum());
    }

    #[test]
    fn set_ipv4_header_checksum() {
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(IPV4_PACKET, 0, true)
                .unwrap();

        assert_eq!(0x067A, ipv4_packet.ipv4_header_checksum());
        ipv4_packet.set_ipv4_header_checksum(0xFFFF);
        assert_eq!(0xFFFF, ipv4_packet.ipv4_header_checksum());
    }

    #[test]
    fn set_options() {
        let mut data = [0xFF_u8; 56];
        copy_into_slice(&mut data, &IPV4_PACKET, 4);
        let mut ipv4_packet =
            DataBuffer::<_, Ipv4<NoPreviousHeader>>::parse_ipv4_alone(&mut data, 4, true).unwrap();

        ipv4_packet
            .ipv4_options_mut()
            .copy_from_slice(&[0x1, 0x2, 0x3, 0x4]);
        assert_eq!(&[0x1, 0x2, 0x3, 0x4], ipv4_packet.ipv4_options());

        ipv4_packet.set_ipv4_ihl(7).unwrap();
        ipv4_packet
            .ipv4_options_mut()
            .copy_from_slice(&[0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9]);
        assert_eq!(
            &[0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9],
            ipv4_packet.ipv4_options()
        );
        ipv4_packet.set_ipv4_ihl(6).unwrap();
        assert_eq!(&[0x2, 0x3, 0x4, 0x5], ipv4_packet.ipv4_options());
        ipv4_packet
            .ipv4_options_mut()
            .copy_from_slice(&[0x6, 0x7, 0x8, 0x9]);
        assert_eq!(&[0x6, 0x7, 0x8, 0x9], ipv4_packet.ipv4_options());
        ipv4_packet.set_ipv4_ihl(5).unwrap();
        assert_eq!(&[0; 0], ipv4_packet.ipv4_options());
    }
}
