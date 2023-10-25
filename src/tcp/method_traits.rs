use crate::checksum::internet_checksum;
use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderInformation, HeaderManipulation, Layer,
};
use crate::error::SetDataOffsetError;
use crate::internal_utils::grow_or_shrink_header_at_end;
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
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[SOURCE_PORT]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn tcp_destination_port(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[DESTINATION_PORT]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn tcp_sequence_number(&self) -> u32 {
        u32::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[SEQUENCE_NUMBER]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn tcp_acknowledgment_number(&self) -> u32 {
        u32::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[ACKNOWLEDGEMENT_NUMBER]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn tcp_data_offset(&self) -> u8 {
        self.data_buffer_starting_at_header(LAYER)[DATA_OFFSET_BYTE] >> DATA_OFFSET_SHIFT
    }

    #[inline]
    fn tcp_reserved_bits(&self) -> u8 {
        self.data_buffer_starting_at_header(LAYER)[RESERVED_BYTE] & RESERVED_MASK
    }

    #[inline]
    fn tcp_flags(&self) -> u8 {
        self.data_buffer_starting_at_header(LAYER)[FLAGS_BYTE]
    }

    #[inline]
    fn tcp_congestion_window_reduced_flag(&self) -> bool {
        (self.data_buffer_starting_at_header(LAYER)[FLAGS_BYTE] & FLAGS_CWR_MASK) != 0
    }

    #[inline]
    fn tcp_ecn_echo_flag(&self) -> bool {
        (self.data_buffer_starting_at_header(LAYER)[FLAGS_BYTE] & FLAGS_ECE_MASK) != 0
    }

    #[inline]
    fn tcp_urgent_pointer_flag(&self) -> bool {
        (self.data_buffer_starting_at_header(LAYER)[FLAGS_BYTE] & FLAGS_URG_MASK) != 0
    }

    #[inline]
    fn tcp_acknowledgement_flag(&self) -> bool {
        (self.data_buffer_starting_at_header(LAYER)[FLAGS_BYTE] & FLAGS_ACK_MASK) != 0
    }

    #[inline]
    fn tcp_push_flag(&self) -> bool {
        (self.data_buffer_starting_at_header(LAYER)[FLAGS_BYTE] & FLAGS_PSH_MASK) != 0
    }

    #[inline]
    fn tcp_reset_flag(&self) -> bool {
        (self.data_buffer_starting_at_header(LAYER)[FLAGS_BYTE] & FLAGS_RST_MASK) != 0
    }

    #[inline]
    fn tcp_synchronize_flag(&self) -> bool {
        (self.data_buffer_starting_at_header(LAYER)[FLAGS_BYTE] & FLAGS_SYN_MASK) != 0
    }

    #[inline]
    fn tcp_fin_flag(&self) -> bool {
        (self.data_buffer_starting_at_header(LAYER)[FLAGS_BYTE] & FLAGS_FIN_MASK) != 0
    }

    #[inline]
    fn tcp_window_size(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[WINDOW_SIZE]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn tcp_checksum(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[CHECKSUM]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn tcp_urgent_pointer(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[URGENT_POINTER]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn tcp_options(&self) -> Option<&[u8]> {
        let data_offset = usize::from(self.tcp_data_offset());
        if data_offset <= *DATA_OFFSET_RANGE.start() {
            None
        } else {
            Some(&self.data_buffer_starting_at_header(LAYER)[OPTIONS_START..data_offset * 4])
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
        self.data_buffer_starting_at_header_mut(LAYER)[SOURCE_PORT]
            .copy_from_slice(&port.to_be_bytes());
    }

    #[inline]
    fn set_tcp_destination_port(&mut self, port: u16) {
        self.data_buffer_starting_at_header_mut(LAYER)[DESTINATION_PORT]
            .copy_from_slice(&port.to_be_bytes());
    }

    #[inline]
    fn set_tcp_sequence_number(&mut self, sequence_number: u32) {
        self.data_buffer_starting_at_header_mut(LAYER)[SEQUENCE_NUMBER]
            .copy_from_slice(&sequence_number.to_be_bytes());
    }

    #[inline]
    fn set_tcp_acknowledgement_number(&mut self, acknowledgement_number: u32) {
        self.data_buffer_starting_at_header_mut(LAYER)[ACKNOWLEDGEMENT_NUMBER]
            .copy_from_slice(&acknowledgement_number.to_be_bytes());
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
        self.data_buffer_starting_at_header_mut(LAYER)[DATA_OFFSET_BYTE] = new_data_offset_byte;
        self.update_ip_length();
        Ok(())
    }

    #[inline]
    fn set_tcp_reserved_bits(&mut self, reserved_bits: u8) {
        let reserved_bits = reserved_bits & RESERVED_MASK;
        self.data_buffer_starting_at_header_mut(LAYER)[RESERVED_BYTE] =
            (self.data_buffer_starting_at_header_mut(LAYER)[RESERVED_BYTE] & !RESERVED_MASK)
                | reserved_bits;
    }

    #[inline]
    fn set_tcp_flags(&mut self, flags: u8) {
        self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] = flags;
    }

    #[inline]
    fn set_tcp_congestion_window_reduced_flag(&mut self, congestion_window_reduced: bool) {
        let congestion_window_reduced = (congestion_window_reduced as u8) << FLAGS_CWR_SHIFT;
        self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] =
            self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] & !FLAGS_CWR_MASK
                | congestion_window_reduced;
    }

    #[inline]
    fn set_tcp_ecn_echo_flag(&mut self, ecn_echo: bool) {
        let ecn_echo = (ecn_echo as u8) << FLAGS_ECE_SHIFT;
        self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] =
            self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] & !FLAGS_ECE_MASK | ecn_echo;
    }

    #[inline]
    fn set_tcp_urgent_pointer_flag(&mut self, urgent_pointer: bool) {
        let urgent_pointer = (urgent_pointer as u8) << FLAGS_URG_SHIFT;
        self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] =
            self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] & !FLAGS_URG_MASK
                | urgent_pointer;
    }

    #[inline]
    fn set_tcp_acknowledgement_flag(&mut self, acknowledgement: bool) {
        let acknowledgement = (acknowledgement as u8) << FLAGS_ACK_SHIFT;
        self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] =
            self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] & !FLAGS_ACK_MASK
                | acknowledgement;
    }

    #[inline]
    fn set_tcp_push_flag(&mut self, push: bool) {
        let push = (push as u8) << FLAGS_PSH_SHIFT;
        self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] =
            self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] & !FLAGS_PSH_MASK | push;
    }

    #[inline]
    fn set_tcp_reset_flag(&mut self, reset: bool) {
        let reset = (reset as u8) << FLAGS_RST_SHIFT;
        self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] =
            self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] & !FLAGS_RST_MASK | reset;
    }

    #[inline]
    fn set_tcp_synchronize_flag(&mut self, synchronize: bool) {
        let synchronize = (synchronize as u8) << FLAGS_SYN_SHIFT;
        self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] =
            self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] & !FLAGS_SYN_MASK
                | synchronize;
    }

    #[inline]
    fn set_tcp_fin_flag(&mut self, fin: bool) {
        self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] =
            self.data_buffer_starting_at_header_mut(LAYER)[FLAGS_BYTE] & !FLAGS_FIN_MASK
                | (fin as u8);
    }

    #[inline]
    fn set_tcp_window_size(&mut self, window_size: u16) {
        self.data_buffer_starting_at_header_mut(LAYER)[WINDOW_SIZE]
            .copy_from_slice(&window_size.to_be_bytes())
    }

    #[inline]
    fn set_tcp_checksum(&mut self, checksum: u16) {
        self.data_buffer_starting_at_header_mut(LAYER)[CHECKSUM]
            .copy_from_slice(&checksum.to_be_bytes())
    }

    #[inline]
    fn set_tcp_urgent_pointer(&mut self, urgent_pointer: u16) {
        self.data_buffer_starting_at_header_mut(LAYER)[URGENT_POINTER]
            .copy_from_slice(&urgent_pointer.to_be_bytes())
    }

    #[inline]
    fn tcp_options_mut(&mut self) -> Option<&mut [u8]> {
        let data_offset_header = usize::from(self.tcp_data_offset());
        if data_offset_header <= *DATA_OFFSET_RANGE.start() {
            None
        } else {
            let data_offset_in_bytes = data_offset_header * 4;
            Some(
                &mut self.data_buffer_starting_at_header_mut(LAYER)
                    [OPTIONS_START..data_offset_in_bytes],
            )
        }
    }

    #[inline]
    fn update_tcp_checksum(&mut self) {
        self.data_buffer_starting_at_header_mut(LAYER)[CHECKSUM].copy_from_slice(&[0, 0]);
        let checksum = self.tcp_calculate_checksum();
        self.data_buffer_starting_at_header_mut(LAYER)[CHECKSUM]
            .copy_from_slice(&checksum.to_be_bytes());
    }
}
