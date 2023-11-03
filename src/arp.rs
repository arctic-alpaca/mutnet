//! ARP type and method traits.

mod error;
mod method_traits;
mod operation_code;
#[cfg(all(feature = "remove_checksum", feature = "verify_arp", kani))]
mod verification;

use crate::data_buffer::traits::{HeaderInformation, HeaderInformationMut, Layer};
use crate::data_buffer::traits::{HeaderInformationExtraction, Payload};
use crate::data_buffer::{
    ArpMarker, BufferIntoInner, DataBuffer, EthernetMarker, Ieee802_1QVlanMarker,
};
use crate::error::UnexpectedBufferEndError;
use crate::internal_utils::{check_and_calculate_data_length, header_start_offset_from_phi};
use crate::no_previous_header::NoPreviousHeaderInformation;
pub use error::*;
pub use method_traits::*;
pub use operation_code::*;

/// ARP metadata.
///
/// Contains meta data about the ARP header in the parsed data buffer.
#[derive(Eq, PartialEq, Hash, Copy, Clone, Debug)]
pub struct Arp<PHI: HeaderInformation + HeaderInformationMut> {
    header_start_offset: usize,
    header_length: usize,
    previous_header_information: PHI,
}

// Marker traits implemented for ARP
impl<PHI> ArpMarker for Arp<PHI> where PHI: HeaderInformation + HeaderInformationMut {}
impl<PHI> EthernetMarker for Arp<PHI> where
    PHI: HeaderInformation + HeaderInformationMut + EthernetMarker
{
}
impl<PHI> Ieee802_1QVlanMarker for Arp<PHI> where
    PHI: HeaderInformation + HeaderInformationMut + Ieee802_1QVlanMarker
{
}

impl<B, PHI> DataBuffer<B, Arp<PHI>>
where
    B: AsRef<[u8]>,
    PHI: HeaderInformation + HeaderInformationMut + Copy,
{
    /// Parses `buf` and creates a new [DataBuffer] for an ARP layer with no previous layers.
    ///
    /// `headroom` indicates the amount of headroom in the provided `buf`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided data buffer is shorter than expected.
    /// - the provided ARP packet's hardware type is not Ethernet or IPv4.
    #[inline]
    pub fn new(
        buf: B,
        headroom: usize,
    ) -> Result<DataBuffer<B, Arp<NoPreviousHeaderInformation>>, ParseArpError> {
        let lower_layer_data_buffer =
            DataBuffer::<B, NoPreviousHeaderInformation>::new(buf, headroom)?;
        DataBuffer::<B, Arp<NoPreviousHeaderInformation>>::new_from_lower(lower_layer_data_buffer)
    }

    /// Consumes the `lower_layer_data_buffer` and creates a new [DataBuffer] with an additional
    /// ARP layer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided data buffer is shorter than expected.
    /// - the provided ARP packet's hardware type is not Ethernet or IPv4.
    #[inline]
    pub fn new_from_lower(
        lower_layer_data_buffer: impl HeaderInformation
            + Payload
            + BufferIntoInner<B>
            + HeaderInformationExtraction<PHI>,
    ) -> Result<DataBuffer<B, Arp<PHI>>, ParseArpError> {
        let previous_header_information = lower_layer_data_buffer.extract_header_information();

        check_and_calculate_data_length::<ParseArpError>(
            lower_layer_data_buffer.payload_length(),
            0,
            HEADER_MIN_LEN,
        )?;

        // Check hardware type to be ethernet, protocol type to be IPv4, hardware address length
        // to be 6 and protocol address length to be 4.
        if lower_layer_data_buffer.payload()[HARDWARE_TYPE.start..=PROTOCOL_ADDRESS_LENGTH]
            != [0x00, 0x01, 0x08, 0x00, 0x6, 0x4]
        {
            return Err(ParseArpError::UnsupportedHardwareOrProtocolFields);
        }

        let result = Self {
            header_information: Arp {
                header_start_offset: header_start_offset_from_phi(previous_header_information),
                header_length: 28,
                previous_header_information: *previous_header_information,
            },
            buffer: lower_layer_data_buffer.buffer_into_inner(),
        };

        if !(1..3).contains(&result.arp_operation_code()) {
            return Err(ParseArpError::InvalidOperationCode {
                operation_code: result.arp_operation_code(),
            });
        }

        Ok(result)
    }
}

impl<B, H> ArpMethods for DataBuffer<B, H>
where
    B: AsRef<[u8]>,
    H: HeaderInformation + HeaderInformationMut + ArpMarker,
{
}
impl<B, H> ArpMethodsMut for DataBuffer<B, H>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    H: HeaderInformation + HeaderInformationMut + ArpMarker,
{
}

impl<PHI> HeaderInformation for Arp<PHI>
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

impl<PHI> HeaderInformationMut for Arp<PHI>
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

#[cfg(test)]
mod tests {
    use crate::arp::{Arp, ArpMethods, ArpMethodsMut};
    use crate::arp::{OperationCode, ParseArpError};
    use crate::data_buffer::traits::{HeaderInformation, Layer};
    use crate::data_buffer::DataBuffer;
    use crate::error::UnexpectedBufferEndError;
    use crate::ether_type::EtherType;
    use crate::no_previous_header::NoPreviousHeaderInformation;
    use crate::test_utils::copy_into_slice;

    // ARP for IPv4
    const ARP_IPV4_REQUEST: [u8; 28] = [
        0x00, 0x01, // Hardware type
        0x08, 0x00, // Protocol type
        0x06, // Hardware address length
        0x04, // Protocol address length
        0x00, 0x01, // Operation
        0x1C, 0xED, 0xA4, 0xE1, 0xD2, 0xA2, // Sender hardware address (MAC address)
        0xC0, 0xA8, 0x0A, 0x01, // Sender protocol address (IPv4 address)
        0x13, 0xE2, 0xAF, 0xE2, 0xD5, 0xA6, // Target hardware address (MAC address)
        0xC0, 0xA8, 0x7A, 0x0E, // Target protocol address (IPv4 address)
    ];

    // ARP for IPv4
    const ARP_IPV4_REPLY: [u8; 28] = [
        0x00, 0x01, // Hardware type
        0x08, 0x00, // Protocol type
        0x06, // Hardware address length
        0x04, // Protocol address length
        0x00, 0x02, // Operation
        0x1C, 0xED, 0xA4, 0xE1, 0xD2, 0xA2, // Sender hardware address (MAC address)
        0xC0, 0xA8, 0x0A, 0x01, // Sender protocol address (IPv4 address)
        0x13, 0xE2, 0xAF, 0xE2, 0xD5, 0xA6, // Target hardware address (MAC address)
        0xC0, 0xA8, 0x7A, 0xE, // Target protocol address (IPv4 address)
    ];

    #[test]
    fn new_request() {
        let arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(1, arp_packet.arp_operation_code());
        assert_eq!(
            Ok(OperationCode::Request),
            arp_packet.arp_typed_operation_code()
        );
    }

    #[test]
    fn new_reply() {
        let arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REPLY, 0).unwrap();
        assert_eq!(2, arp_packet.arp_operation_code());
        assert_eq!(
            Ok(OperationCode::Reply),
            arp_packet.arp_typed_operation_code()
        );
    }

    #[test]
    fn new_wrong_hardware_type() {
        let mut no_ethernet_data = ARP_IPV4_REQUEST;
        no_ethernet_data[1] = 10;
        assert_eq!(
            Err(ParseArpError::UnsupportedHardwareOrProtocolFields),
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(no_ethernet_data, 0)
        );
    }

    #[test]
    fn new_wrong_protocol_type() {
        let mut no_ipv4_data = ARP_IPV4_REQUEST;
        no_ipv4_data[2] = 10;
        assert_eq!(
            Err(ParseArpError::UnsupportedHardwareOrProtocolFields),
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(no_ipv4_data, 0)
        );
    }

    #[test]
    fn new_wrong_hardware_address_length() {
        let mut wrong_hardware_address_length = ARP_IPV4_REQUEST;
        wrong_hardware_address_length[4] = 10;
        assert_eq!(
            Err(ParseArpError::UnsupportedHardwareOrProtocolFields),
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(
                wrong_hardware_address_length,
                0
            )
        );
    }

    #[test]
    fn new_wrong_protocol_address_length() {
        let mut wrong_protocol_address_length = ARP_IPV4_REQUEST;
        wrong_protocol_address_length[5] = 10;
        assert_eq!(
            Err(ParseArpError::UnsupportedHardwareOrProtocolFields),
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(
                wrong_protocol_address_length,
                0
            )
        );
    }

    #[test]
    fn new_data_buffer_too_short() {
        assert_eq!(
            Err(ParseArpError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 28,
                    actual_length: 27,
                }
            )),
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(&ARP_IPV4_REQUEST[..27], 0)
        );
    }

    #[test]
    fn new_headroom_out_of_range() {
        assert_eq!(
            Err(ParseArpError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 29,
                    actual_length: 28,
                }
            )),
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(&ARP_IPV4_REQUEST, 29)
        );
    }

    #[test]
    fn new_wrong_operation_code() {
        let mut wrong_operation_code = ARP_IPV4_REQUEST;
        wrong_operation_code[7] = 3;
        assert_eq!(
            Err(ParseArpError::InvalidOperationCode { operation_code: 3 }),
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(wrong_operation_code, 0)
        );
    }

    #[test]
    fn arp_hardware_type() {
        let arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(1, arp_packet.arp_hardware_type());
    }

    #[test]
    fn arp_protocol_type() {
        let arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(0x800, arp_packet.arp_protocol_type());
    }

    #[test]
    fn arp_typed_protocol_type() {
        let arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(Ok(EtherType::Ipv4), arp_packet.arp_typed_protocol_type());
    }

    #[test]
    fn arp_operation_code() {
        let arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(1, arp_packet.arp_operation_code());
    }

    #[test]
    fn arp_typed_operation_code() {
        let arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(
            Ok(OperationCode::Request),
            arp_packet.arp_typed_operation_code()
        );
    }

    #[test]
    fn arp_hardware_address_length() {
        let arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(0x06, arp_packet.arp_hardware_address_length());
    }

    #[test]
    fn arp_protocol_address_length() {
        let arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(0x04, arp_packet.arp_protocol_address_length());
    }

    #[test]
    fn arp_sender_hardware_address() {
        let arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(
            [0x1C, 0xED, 0xA4, 0xE1, 0xD2, 0xA2,],
            arp_packet.arp_sender_hardware_address()
        );
    }

    #[test]
    fn arp_sender_protocol_address() {
        let arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(
            [0xC0, 0xA8, 0x0A, 0x01,],
            arp_packet.arp_sender_protocol_address()
        );
    }

    #[test]
    fn arp_target_hardware_address() {
        let arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(
            [0x13, 0xE2, 0xAF, 0xE2, 0xD5, 0xA6,],
            arp_packet.arp_target_hardware_address()
        );
    }

    #[test]
    fn arp_target_protocol_address() {
        let arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(
            [0xC0, 0xA8, 0x7A, 0x0E,],
            arp_packet.arp_target_protocol_address()
        );
    }

    #[test]
    fn headroom() {
        let arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(0, arp_packet.headroom_internal());
    }

    #[test]
    fn arp_set_operation_code() {
        let mut arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(1, arp_packet.arp_operation_code());
        arp_packet.set_arp_operation_code(OperationCode::Reply);
        assert_eq!(2, arp_packet.arp_operation_code());
    }

    #[test]
    fn arp_set_sender_hardware_address() {
        let mut arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(
            [0x1C, 0xED, 0xA4, 0xE1, 0xD2, 0xA2,],
            arp_packet.arp_sender_hardware_address()
        );
        arp_packet.set_arp_sender_hardware_address(&[0xFF; 6]);
        assert_eq!([0xFF; 6], arp_packet.arp_sender_hardware_address());
    }

    #[test]
    fn arp_set_sender_protocol_address() {
        let mut arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(
            [0xC0, 0xA8, 0x0A, 0x01,],
            arp_packet.arp_sender_protocol_address()
        );
        arp_packet.set_arp_sender_protocol_address(&[0xFF; 4]);
        assert_eq!([0xFF; 4], arp_packet.arp_sender_protocol_address());
    }

    #[test]
    fn arp_set_target_hardware_address() {
        let mut arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(
            [0x13, 0xE2, 0xAF, 0xE2, 0xD5, 0xA6,],
            arp_packet.arp_target_hardware_address()
        );
        arp_packet.set_arp_target_hardware_address(&[0xFF; 6]);
        assert_eq!([0xFF; 6], arp_packet.arp_target_hardware_address());
    }

    #[test]
    fn arp_set_target_protocol_address() {
        let mut arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(ARP_IPV4_REQUEST, 0).unwrap();
        assert_eq!(
            [0xC0, 0xA8, 0x7A, 0x0E,],
            arp_packet.arp_target_protocol_address()
        );
        arp_packet.set_arp_target_protocol_address(&[0xFF; 4]);
        assert_eq!([0xFF; 4], arp_packet.arp_target_protocol_address());
    }

    #[test]
    fn arp_headroom() {
        let mut data = [0_u8; 100];
        copy_into_slice(&mut data, &ARP_IPV4_REPLY, 36);
        let arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(&mut data, 36).unwrap();

        assert_eq!(36, arp_packet.headroom_internal());
        assert_eq!(0, arp_packet.header_start_offset(Layer::Arp));
        assert_eq!(28, arp_packet.header_length(Layer::Arp));

        let arp_packet =
            DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(&mut data, 36).unwrap();
        assert_eq!(36, arp_packet.headroom_internal());
        assert_eq!(0, arp_packet.header_start_offset(Layer::Arp));
        assert_eq!(28, arp_packet.header_length(Layer::Arp));
    }
}
