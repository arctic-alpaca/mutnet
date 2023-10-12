use crate::checksum::internet_checksum_intermediary;
use crate::data_buffer::traits::{
    HeaderInformation, HeaderInformationMut, HeaderManipulation, Layer,
};
use crate::error::{NotEnoughHeadroomError, UnexpectedBufferEndError};
use crate::ipv4::Ipv4Methods;
use crate::ipv6::Ipv6Methods;
use core::cmp::Ordering;

#[inline]
pub(crate) fn check_and_calculate_data_length<E>(
    buf_len: usize,
    headroom: usize,
    expected_data_length: usize,
) -> Result<usize, E>
where
    E: From<UnexpectedBufferEndError>,
{
    let actual_data_length = buf_len.saturating_sub(headroom);

    if actual_data_length < expected_data_length {
        return Err(UnexpectedBufferEndError {
            expected_length: expected_data_length,
            actual_length: actual_data_length,
        }
        .into());
    }
    Ok(actual_data_length)
}

#[inline]
pub(crate) fn header_start_offset_from_phi<PHI>(previous_header_information: &PHI) -> usize
where
    PHI: HeaderInformation + HeaderInformationMut,
{
    previous_header_information.header_start_offset(previous_header_information.layer())
        + previous_header_information.header_length(previous_header_information.layer())
}

#[inline]
pub(crate) fn grow_or_shrink_header_at_end(
    header: &mut impl HeaderManipulation,
    current_size_in_bytes: usize,
    new_size_in_bytes: usize,
    layer: Layer,
) -> Result<(), NotEnoughHeadroomError> {
    match current_size_in_bytes.cmp(&new_size_in_bytes) {
        Ordering::Less => {
            let difference = new_size_in_bytes - current_size_in_bytes;
            header.grow_header(current_size_in_bytes, difference, layer)?;
        }
        Ordering::Equal => {}
        Ordering::Greater => {
            let difference = current_size_in_bytes - new_size_in_bytes;
            header.shrink_header(new_size_in_bytes, difference, layer);
        }
    }
    Ok(())
}

#[inline]
pub(crate) fn pseudoheader_checksum_ipv6_internal(
    ipv6: &impl Ipv6Methods,
    tcp_udp_length: usize,
    protocol_next_header: u8,
) -> u64 {
    let tcp_udp_length = (tcp_udp_length as u32).to_be_bytes();
    let mut checksum = internet_checksum_intermediary::<4>(&ipv6.ipv6_source());
    checksum += internet_checksum_intermediary::<4>(&ipv6.ipv6_destination());
    checksum += internet_checksum_intermediary::<4>(&[
        tcp_udp_length[0],
        tcp_udp_length[1],
        tcp_udp_length[2],
        tcp_udp_length[3],
    ]);
    checksum += internet_checksum_intermediary::<4>(&[0_u8, 0, 0, protocol_next_header]);
    checksum
}

#[inline]
pub(crate) fn pseudoheader_checksum_ipv4_internal(
    ipv6: &impl Ipv4Methods,
    tcp_udp_length: usize,
    protocol_next_header: u8,
) -> u64 {
    let tcp_udp_length = (tcp_udp_length as u16).to_be_bytes();

    let mut checksum = internet_checksum_intermediary::<4>(&ipv6.ipv4_source());
    checksum += internet_checksum_intermediary::<4>(&ipv6.ipv4_destination());
    checksum += internet_checksum_intermediary::<4>(&[
        0_u8,
        protocol_next_header,
        tcp_udp_length[0],
        tcp_udp_length[1],
    ]);
    checksum
}
