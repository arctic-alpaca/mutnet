use crate::checksum::internet_checksum;
use crate::data_buffer::{
    BufferAccess, BufferAccessMut, HeaderInformation, HeaderManipulation, Layer,
};
use crate::udp::SetLengthError;
use crate::utility_traits::{TcpUdpChecksum, UpdateIpLength};
use core::ops::Range;

pub(crate) const SOURCE_PORT: Range<usize> = 0..2;
pub(crate) const DESTINATION_PORT: Range<usize> = 2..4;
pub(crate) const LENGTH: Range<usize> = 4..6;
pub(crate) const CHECKSUM: Range<usize> = 6..8;

pub(crate) const HEADER_MIN_LEN: usize = 8;

pub(crate) const LAYER: Layer = Layer::Udp;

// Length manipulating methods:
// - set_udp_length (has proof)

pub trait UdpMethods: HeaderInformation + TcpUdpChecksum + BufferAccess {
    #[inline]
    fn udp_source_port(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[SOURCE_PORT]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn udp_destination_port(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[DESTINATION_PORT]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn udp_length(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[LENGTH]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn udp_checksum(&self) -> u16 {
        u16::from_be_bytes(
            self.data_buffer_starting_at_header(LAYER)[CHECKSUM]
                .try_into()
                .unwrap(),
        )
    }

    #[inline]
    fn udp_calculate_checksum(&self) -> u16 {
        let checksum = self.pseudoheader_checksum();

        internet_checksum::<4>(checksum, self.data_buffer_starting_at_header(LAYER))
    }
}

pub trait UdpMethodsMut:
    HeaderInformation
    + HeaderManipulation
    + BufferAccessMut
    + UdpMethods
    + TcpUdpChecksum
    + UpdateIpLength
    + Sized
{
    #[inline]
    fn set_udp_source_port(&mut self, port: u16) {
        self.data_buffer_starting_at_header_mut(LAYER)[SOURCE_PORT]
            .copy_from_slice(&port.to_be_bytes());
    }

    #[inline]
    fn set_udp_destination_port(&mut self, port: u16) {
        self.data_buffer_starting_at_header_mut(LAYER)[DESTINATION_PORT]
            .copy_from_slice(&port.to_be_bytes());
    }

    #[inline]
    fn set_udp_length(&mut self, length: u16) -> Result<(), SetLengthError> {
        let length_usize = usize::from(length);

        if length_usize < HEADER_MIN_LEN {
            return Err(SetLengthError::LengthTooSmall {
                length: length_usize,
            });
        }

        let data_length = self.header_start_offset(LAYER) + length_usize;
        self.set_data_length(data_length, self.buffer_length())?;

        self.data_buffer_starting_at_header_mut(LAYER)[LENGTH]
            .copy_from_slice(&length.to_be_bytes());
        self.update_ip_length();
        Ok(())
    }

    #[inline]
    fn set_udp_checksum(&mut self, checksum: u16) {
        self.data_buffer_starting_at_header_mut(LAYER)[CHECKSUM]
            .copy_from_slice(&checksum.to_be_bytes())
    }

    #[inline]
    fn update_udp_checksum(&mut self) {
        self.data_buffer_starting_at_header_mut(LAYER)[CHECKSUM].copy_from_slice(&[0, 0]);
        let checksum = self.udp_calculate_checksum();
        self.data_buffer_starting_at_header_mut(LAYER)[CHECKSUM]
            .copy_from_slice(&checksum.to_be_bytes());
    }
}
