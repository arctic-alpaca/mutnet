use crate::checksum::internet_checksum_intermediary;
use crate::data_buffer::traits::{HeaderManipulation, HeaderMetadata, HeaderMetadataMut, Layer};
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
pub(crate) fn header_start_offset_from_phi<PHM>(previous_header_metadata: &PHM) -> usize
where
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    previous_header_metadata.header_start_offset(previous_header_metadata.layer())
        + previous_header_metadata.header_length(previous_header_metadata.layer())
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
pub(crate) fn pseudo_header_checksum_ipv6_internal(
    ipv6: &impl Ipv6Methods,
    protocol_next_header: u8,
) -> u64 {
    let length = (u32::from(ipv6.ipv6_payload_length())
        - ipv6.header_length(Layer::Ipv6Ext) as u32)
        .to_be_bytes();
    let mut checksum = internet_checksum_intermediary::<4>(&ipv6.ipv6_source());
    checksum += internet_checksum_intermediary::<4>(&ipv6.ipv6_destination());
    checksum += internet_checksum_intermediary::<4>(&[length[0], length[1], length[2], length[3]]);
    checksum += internet_checksum_intermediary::<4>(&[0_u8, 0, 0, protocol_next_header]);
    checksum
}

#[inline]
pub(crate) fn pseudo_header_checksum_ipv4_internal(
    ipv4: &impl Ipv4Methods,
    protocol_next_header: u8,
) -> u64 {
    let length = (ipv4.ipv4_total_length() - ipv4.header_length(Layer::Ipv4) as u16).to_be_bytes();

    let mut checksum = internet_checksum_intermediary::<4>(&ipv4.ipv4_source());
    checksum += internet_checksum_intermediary::<4>(&ipv4.ipv4_destination());
    checksum +=
        internet_checksum_intermediary::<4>(&[0_u8, protocol_next_header, length[0], length[1]]);
    checksum
}
