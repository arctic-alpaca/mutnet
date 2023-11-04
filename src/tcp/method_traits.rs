use crate::checksum::internet_checksum;
use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderInformation, HeaderManipulation, Layer,
};
use crate::internal_utils::grow_or_shrink_header_at_end;
use crate::tcp::SetDataOffsetError;
use crate::utility_traits::{TcpUdpChecksum, UpdateIpLength};
use core::ops::Range;
use core::ops::RangeInclusive;

pub(crate) const SOURCE_PORT: Range<usize> = 0..2;
pub(crate) const DESTINATION_PORT: Range<usize> = 2..4;
pub(crate) const SEQUENCE_NUMBER: Range<usize> = 4..8;
pub(crate) const ACKNOWLEDGEMENT_NUMBER: Range<usize> = 8..12;
pub(crate) const DATA_OFFSET_BYTE: usize = 12;
pub(crate) const _DATA_OFFSET_MASK: u8 = 0b1111_0000;
pub(crate) const DATA_OFFSET_SHIFT: usize = 4;
pub(crate) const RESERVED_BYTE: usize = 12;
pub(crate) const RESERVED_MASK: u8 = 0b0000_1111;
pub(crate) const FLAGS_BYTE: usize = 13;
pub(crate) const FLAGS_CWR_MASK: u8 = 0b1000_0000;
pub(crate) const FLAGS_CWR_SHIFT: usize = 7;
pub(crate) const FLAGS_ECE_MASK: u8 = 0b0100_0000;
pub(crate) const FLAGS_ECE_SHIFT: usize = 6;
pub(crate) const FLAGS_URG_MASK: u8 = 0b0010_0000;
pub(crate) const FLAGS_URG_SHIFT: usize = 5;
pub(crate) const FLAGS_ACK_MASK: u8 = 0b0001_0000;
pub(crate) const FLAGS_ACK_SHIFT: usize = 4;
pub(crate) const FLAGS_PSH_MASK: u8 = 0b0000_1000;
pub(crate) const FLAGS_PSH_SHIFT: usize = 3;
pub(crate) const FLAGS_RST_MASK: u8 = 0b0000_0100;
pub(crate) const FLAGS_RST_SHIFT: usize = 2;
pub(crate) const FLAGS_SYN_MASK: u8 = 0b0000_0010;
pub(crate) const FLAGS_SYN_SHIFT: usize = 1;
pub(crate) const FLAGS_FIN_MASK: u8 = 0b0000_0001;
pub(crate) const WINDOW_SIZE: Range<usize> = 14..16;
pub(crate) const CHECKSUM: Range<usize> = 16..18;
pub(crate) const URGENT_POINTER: Range<usize> = 18..20;
pub(crate) const OPTIONS_START: usize = 20;

pub(crate) const HEADER_MIN_LEN: usize = 20;

pub(crate) const DATA_OFFSET_RANGE: RangeInclusive<usize> = 5..=15;

pub(crate) const LAYER: Layer = Layer::Tcp;

// Length manipulating methods:
// - set_tcp_data_offset (has proof)

pub trait TcpMethods: HeaderInformation + TcpUdpChecksum + BufferAccess {
    #[inline]
    fn tcp_source_port(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, SOURCE_PORT))
    }

    #[inline]
    fn tcp_destination_port(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, DESTINATION_PORT))
    }

    #[inline]
    fn tcp_sequence_number(&self) -> u32 {
        u32::from_be_bytes(self.read_array(LAYER, SEQUENCE_NUMBER))
    }

    #[inline]
    fn tcp_acknowledgment_number(&self) -> u32 {
        u32::from_be_bytes(self.read_array(LAYER, ACKNOWLEDGEMENT_NUMBER))
    }

    #[inline]
    fn tcp_data_offset(&self) -> u8 {
        self.read_value(LAYER, DATA_OFFSET_BYTE) >> DATA_OFFSET_SHIFT
    }

    #[inline]
    fn tcp_reserved_bits(&self) -> u8 {
        self.read_value(LAYER, RESERVED_BYTE) & RESERVED_MASK
    }

    #[inline]
    fn tcp_flags(&self) -> u8 {
        self.read_value(LAYER, FLAGS_BYTE)
    }

    #[inline]
    fn tcp_congestion_window_reduced_flag(&self) -> bool {
        (self.read_value(LAYER, FLAGS_BYTE) & FLAGS_CWR_MASK) != 0
    }

    #[inline]
    fn tcp_ecn_echo_flag(&self) -> bool {
        (self.read_value(LAYER, FLAGS_BYTE) & FLAGS_ECE_MASK) != 0
    }

    #[inline]
    fn tcp_urgent_pointer_flag(&self) -> bool {
        (self.read_value(LAYER, FLAGS_BYTE) & FLAGS_URG_MASK) != 0
    }

    #[inline]
    fn tcp_acknowledgement_flag(&self) -> bool {
        (self.read_value(LAYER, FLAGS_BYTE) & FLAGS_ACK_MASK) != 0
    }

    #[inline]
    fn tcp_push_flag(&self) -> bool {
        (self.read_value(LAYER, FLAGS_BYTE) & FLAGS_PSH_MASK) != 0
    }

    #[inline]
    fn tcp_reset_flag(&self) -> bool {
        (self.read_value(LAYER, FLAGS_BYTE) & FLAGS_RST_MASK) != 0
    }

    #[inline]
    fn tcp_synchronize_flag(&self) -> bool {
        (self.read_value(LAYER, FLAGS_BYTE) & FLAGS_SYN_MASK) != 0
    }

    #[inline]
    fn tcp_fin_flag(&self) -> bool {
        (self.read_value(LAYER, FLAGS_BYTE) & FLAGS_FIN_MASK) != 0
    }

    #[inline]
    fn tcp_window_size(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, WINDOW_SIZE))
    }

    #[inline]
    fn tcp_checksum(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, CHECKSUM))
    }

    #[inline]
    fn tcp_urgent_pointer(&self) -> u16 {
        u16::from_be_bytes(self.read_array(LAYER, URGENT_POINTER))
    }

    #[inline]
    fn tcp_options(&self) -> Option<&[u8]> {
        let data_offset = usize::from(self.tcp_data_offset());
        if data_offset <= *DATA_OFFSET_RANGE.start() {
            None
        } else {
            Some(self.read_slice(LAYER, OPTIONS_START..data_offset * 4))
        }
    }

    #[inline]
    fn tcp_calculate_checksum(&self) -> u16 {
        let checksum = self.pseudoheader_checksum();

        internet_checksum::<4>(checksum, self.data_buffer_starting_at_header(LAYER))
    }
}

pub trait TcpMethodsMut:
    HeaderInformation
    + HeaderManipulation
    + BufferAccessMut
    + TcpMethods
    + TcpUdpChecksum
    + UpdateIpLength
    + Sized
{
    #[inline]
    fn set_tcp_source_port(&mut self, port: u16) {
        self.write_slice(LAYER, SOURCE_PORT, &port.to_be_bytes());
    }

    #[inline]
    fn set_tcp_destination_port(&mut self, port: u16) {
        self.write_slice(LAYER, DESTINATION_PORT, &port.to_be_bytes());
    }

    #[inline]
    fn set_tcp_sequence_number(&mut self, sequence_number: u32) {
        self.write_slice(LAYER, SEQUENCE_NUMBER, &sequence_number.to_be_bytes());
    }

    #[inline]
    fn set_tcp_acknowledgement_number(&mut self, acknowledgement_number: u32) {
        self.write_slice(
            LAYER,
            ACKNOWLEDGEMENT_NUMBER,
            &acknowledgement_number.to_be_bytes(),
        );
    }

    /// Manipulates the header's length
    #[inline]
    fn set_tcp_data_offset(&mut self, data_offset: u8) -> Result<(), SetDataOffsetError> {
        let new_data_offset_usize = usize::from(data_offset);
        if !DATA_OFFSET_RANGE.contains(&new_data_offset_usize) {
            return Err(SetDataOffsetError::InvalidDataOffset {
                data_offset: new_data_offset_usize,
            });
        }
        let current_data_offset_in_bytes = usize::from(self.tcp_data_offset()) * 4;
        let new_data_offset_in_bytes = new_data_offset_usize * 4;
        grow_or_shrink_header_at_end(
            self,
            current_data_offset_in_bytes,
            new_data_offset_in_bytes,
            LAYER,
        )?;

        let new_data_offset_byte = data_offset << DATA_OFFSET_SHIFT;
        self.write_value(LAYER, DATA_OFFSET_BYTE, new_data_offset_byte);
        self.update_ip_length();
        Ok(())
    }

    #[inline]
    fn set_tcp_reserved_bits(&mut self, mut reserved_bits: u8) {
        reserved_bits &= RESERVED_MASK;
        reserved_bits |= self.read_value(LAYER, RESERVED_BYTE) & !RESERVED_MASK;
        self.write_value(LAYER, RESERVED_BYTE, reserved_bits);
    }

    #[inline]
    fn set_tcp_flags(&mut self, flags: u8) {
        self.write_value(LAYER, FLAGS_BYTE, flags);
    }

    #[inline]
    fn set_tcp_congestion_window_reduced_flag(&mut self, congestion_window_reduced: bool) {
        let mut congestion_window_reduced = (congestion_window_reduced as u8) << FLAGS_CWR_SHIFT;
        congestion_window_reduced |= self.read_value(LAYER, FLAGS_BYTE) & !FLAGS_CWR_MASK;
        self.write_value(LAYER, FLAGS_BYTE, congestion_window_reduced);
    }

    #[inline]
    fn set_tcp_ecn_echo_flag(&mut self, ecn_echo: bool) {
        let mut ecn_echo = (ecn_echo as u8) << FLAGS_ECE_SHIFT;
        ecn_echo |= self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] & !FLAGS_ECE_MASK;
        self.write_value(LAYER, FLAGS_BYTE, ecn_echo);
    }

    #[inline]
    fn set_tcp_urgent_pointer_flag(&mut self, urgent_pointer: bool) {
        let mut urgent_pointer = (urgent_pointer as u8) << FLAGS_URG_SHIFT;
        urgent_pointer |= self.read_value(LAYER, FLAGS_BYTE) & !FLAGS_URG_MASK;
        self.write_value(LAYER, FLAGS_BYTE, urgent_pointer);
    }

    #[inline]
    fn set_tcp_acknowledgement_flag(&mut self, acknowledgement: bool) {
        let mut acknowledgement = (acknowledgement as u8) << FLAGS_ACK_SHIFT;
        acknowledgement |= self.read_value(LAYER, FLAGS_BYTE) & !FLAGS_ACK_MASK;
        self.write_value(LAYER, FLAGS_BYTE, acknowledgement);
    }

    #[inline]
    fn set_tcp_push_flag(&mut self, push: bool) {
        let mut push = (push as u8) << FLAGS_PSH_SHIFT;
        push |= self.read_value(LAYER, FLAGS_BYTE) & !FLAGS_PSH_MASK;
        self.write_value(LAYER, FLAGS_BYTE, push);
    }

    #[inline]
    fn set_tcp_reset_flag(&mut self, reset: bool) {
        let mut reset = (reset as u8) << FLAGS_RST_SHIFT;
        reset |= self.read_value(LAYER, FLAGS_BYTE) & !FLAGS_RST_MASK;
        self.write_value(LAYER, FLAGS_BYTE, reset);
    }

    #[inline]
    fn set_tcp_synchronize_flag(&mut self, synchronize: bool) {
        let mut synchronize = (synchronize as u8) << FLAGS_SYN_SHIFT;
        synchronize |= self.read_value(LAYER, FLAGS_BYTE) & !FLAGS_SYN_MASK;
        self.write_value(LAYER, FLAGS_BYTE, synchronize);
    }

    #[inline]
    fn set_tcp_fin_flag(&mut self, fin: bool) {
        let fin_flag = self.read_value(LAYER, FLAGS_BYTE) & !FLAGS_FIN_MASK | (fin as u8);
        self.write_value(LAYER, FLAGS_BYTE, fin_flag);
    }

    #[inline]
    fn set_tcp_window_size(&mut self, window_size: u16) {
        self.write_slice(LAYER, WINDOW_SIZE, &window_size.to_be_bytes())
    }

    #[inline]
    fn set_tcp_checksum(&mut self, checksum: u16) {
        self.write_slice(LAYER, CHECKSUM, &checksum.to_be_bytes());
    }

    #[inline]
    fn set_tcp_urgent_pointer(&mut self, urgent_pointer: u16) {
        self.write_slice(LAYER, URGENT_POINTER, &urgent_pointer.to_be_bytes())
    }

    #[inline]
    fn tcp_options_mut(&mut self) -> Option<&mut [u8]> {
        let data_offset_header = usize::from(self.tcp_data_offset());
        if data_offset_header <= *DATA_OFFSET_RANGE.start() {
            None
        } else {
            let data_offset_in_bytes = data_offset_header * 4;
            Some(self.get_slice_mut(LAYER, OPTIONS_START..data_offset_in_bytes))
        }
    }

    #[inline]
    fn update_tcp_checksum(&mut self) {
        self.write_slice(LAYER, CHECKSUM, &[0, 0]);
        let checksum = self.tcp_calculate_checksum();
        self.write_slice(LAYER, CHECKSUM, &checksum.to_be_bytes());
    }
}
