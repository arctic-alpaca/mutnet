use crate::addresses::ipv6::Ipv6Addr;
use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderInformation, HeaderManipulation, Layer,
};
use crate::internet_protocol::{InternetProtocolNumber, NoRecognizedInternetProtocolNumberError};
use crate::ipv6::SetPayloadLengthError;

pub(crate) static VERSION_BYTE: usize = 0;
pub(crate) static VERSION_SHIFT: usize = 4;

pub(crate) static TRAFFIC_CLASS_BYTE_1: usize = 0;
pub(crate) static TRAFFIC_CLASS_BYTE_2: usize = 1;
pub(crate) static TRAFFIC_CLASS_MASK_BYTE_1: u8 = 0b0000_1111;
pub(crate) static TRAFFIC_CLASS_MASK_BYTE_2: u8 = 0b1111_0000;
pub(crate) static TRAFFIC_CLASS_SHIFT_BYTE_1: usize = 4;
pub(crate) static TRAFFIC_CLASS_SHIFT_BYTE_2: usize = 4;

pub(crate) static FLOW_LABEL_START: usize = 1;
pub(crate) static FLOW_LABEL_END: usize = 4;
pub(crate) static FLOW_LABEL_MASK_BYTE_1: u8 = 0b0000_1111;

pub(crate) static PAYLOAD_LENGTH_START: usize = 4;
pub(crate) static PAYLOAD_LENGTH_END: usize = 6;

pub(crate) static NEXT_HEADER: usize = 6;

pub(crate) static HOP_LIMIT: usize = 7;

pub(crate) static SOURCE_START: usize = 8;
pub(crate) static SOURCE_END: usize = 24;

pub(crate) static DESTINATION_START: usize = 24;
pub(crate) static DESTINATION_END: usize = 40;

pub(crate) static HEADER_MIN_LEN: usize = 40;

pub(crate) static LAYER: Layer = Layer::Ipv6;

// Length manipulating methods:
// - set_ipv6_payload_length (has proof)

pub trait Ipv6Methods: HeaderInformation + BufferAccess {
    #[inline]
    fn ipv6_version(&self) -> u8 {
        self.data_buffer_starting_at_header(LAYER)[VERSION_BYTE] >> VERSION_SHIFT
    }

    #[inline]
    fn ipv6_traffic_class(&self) -> u8 {
        let higher_bits = self.data_buffer_starting_at_header(LAYER)[TRAFFIC_CLASS_BYTE_1]
            << TRAFFIC_CLASS_SHIFT_BYTE_1;
        let lower_bits = self.data_buffer_starting_at_header(LAYER)[TRAFFIC_CLASS_BYTE_2]
            >> TRAFFIC_CLASS_SHIFT_BYTE_2;
        higher_bits | lower_bits
    }

    #[inline]
    fn ipv6_flow_label(&self) -> u32 {
        let flow_label_slice =
            &self.data_buffer_starting_at_header(LAYER)[FLOW_LABEL_START..FLOW_LABEL_END];
        let lower_two_octets = u32::from(u16::from_be_bytes(
            flow_label_slice[1..].try_into().unwrap(),
        ));
        let first_four_bits = u32::from(flow_label_slice[0] & FLOW_LABEL_MASK_BYTE_1) << 16;
        first_four_bits | lower_two_octets
    }

    #[inline]
    fn ipv6_payload_length(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[PAYLOAD_LENGTH_START..PAYLOAD_LENGTH_END]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn ipv6_next_header(&self) -> u8 {
        self.data_buffer_starting_at_header(LAYER)[NEXT_HEADER]
    }

    #[inline]
    fn ipv6_typed_next_header(
        &self,
    ) -> Result<InternetProtocolNumber, NoRecognizedInternetProtocolNumberError> {
        self.data_buffer_starting_at_header(LAYER)[NEXT_HEADER].try_into()
    }

    #[inline]
    fn ipv6_hop_limit(&self) -> u8 {
        self.data_buffer_starting_at_header(LAYER)[HOP_LIMIT]
    }

    #[inline]
    fn ipv6_source(&self) -> Ipv6Addr {
        self.data_buffer_starting_at_header(LAYER)[SOURCE_START..SOURCE_END]
            .try_into()
            .unwrap()
    }

    #[inline]
    fn ipv6_destination(&self) -> Ipv6Addr {
        self.data_buffer_starting_at_header(LAYER)[DESTINATION_START..DESTINATION_END]
            .try_into()
            .unwrap()
    }
}

pub trait Ipv6MethodsMut: HeaderManipulation + BufferAccessMut + Ipv6Methods + Sized {
    #[inline]
    fn set_ipv6_traffic_class(&mut self, traffic_class: u8) {
        let higher_bits = traffic_class >> TRAFFIC_CLASS_SHIFT_BYTE_1;
        let lower_bits = traffic_class << TRAFFIC_CLASS_SHIFT_BYTE_2;

        self.data_buffer_starting_at_header_mut(LAYER)[TRAFFIC_CLASS_BYTE_1] = (self
            .data_buffer_starting_at_header_mut(LAYER)[TRAFFIC_CLASS_BYTE_1]
            & !TRAFFIC_CLASS_MASK_BYTE_1)
            | higher_bits;
        self.data_buffer_starting_at_header_mut(LAYER)[TRAFFIC_CLASS_BYTE_2] = (self
            .data_buffer_starting_at_header_mut(LAYER)[TRAFFIC_CLASS_BYTE_2]
            & !TRAFFIC_CLASS_MASK_BYTE_2)
            | lower_bits;
    }

    #[inline]
    fn set_ipv6_flow_label(&mut self, flow_label: u32) {
        let mut flow_label_bytes = flow_label.to_be_bytes();
        flow_label_bytes[1] |= self.data_buffer_starting_at_header_mut(LAYER)[FLOW_LABEL_START]
            & !FLOW_LABEL_MASK_BYTE_1;

        self.data_buffer_starting_at_header_mut(LAYER)[FLOW_LABEL_START..FLOW_LABEL_END]
            .copy_from_slice(&flow_label_bytes[1..]);
    }

    #[inline]
    fn set_ipv6_payload_length(
        &mut self,
        payload_length: u16,
    ) -> Result<(), SetPayloadLengthError> {
        let payload_length_usize = usize::from(payload_length);
        let data_length = self.header_start_offset(LAYER) + HEADER_MIN_LEN + payload_length_usize;

        // Don't allow cutting already parsed upper layers
        if self.layer() != LAYER {
            let intermediate_upper_headers_length = self.header_start_offset(self.layer())
                - self.header_start_offset(LAYER)
                - HEADER_MIN_LEN;

            let highest_header_length = self.header_length(self.layer());
            if payload_length_usize < intermediate_upper_headers_length + highest_header_length {
                return Err(SetPayloadLengthError::CannotCutUpperLayerHeader);
            }
        }

        self.set_data_length(data_length, self.buffer_length())?;

        self.data_buffer_starting_at_header_mut(LAYER)[PAYLOAD_LENGTH_START..PAYLOAD_LENGTH_END]
            .copy_from_slice(&payload_length.to_be_bytes());
        Ok(())
    }

    #[inline]
    fn set_ipv6_next_header(&mut self, next_header: u8) {
        self.data_buffer_starting_at_header_mut(LAYER)[NEXT_HEADER] = next_header;
    }

    #[inline]
    fn set_ipv6_hop_limit(&mut self, hop_limit: u8) {
        self.data_buffer_starting_at_header_mut(LAYER)[HOP_LIMIT] = hop_limit;
    }

    #[inline]
    fn set_ipv6_source(&mut self, source: Ipv6Addr) {
        self.data_buffer_starting_at_header_mut(LAYER)[SOURCE_START..SOURCE_END]
            .copy_from_slice(&source);
    }

    #[inline]
    fn set_ipv6_destination(&mut self, destination: Ipv6Addr) {
        self.data_buffer_starting_at_header_mut(LAYER)[DESTINATION_START..DESTINATION_END]
            .copy_from_slice(&destination);
    }
}

pub(crate) trait UpdateIpv6Length:
    HeaderManipulation + BufferAccessMut + Ipv6Methods + Sized
{
    #[inline]
    fn update_ipv6_length(&mut self) {
        let ipv6_length = self.data_length() - self.header_start_offset(LAYER) - HEADER_MIN_LEN;

        self.data_buffer_starting_at_header_mut(LAYER)[PAYLOAD_LENGTH_START..PAYLOAD_LENGTH_END]
            .copy_from_slice(&(ipv6_length as u16).to_be_bytes());
    }
}
