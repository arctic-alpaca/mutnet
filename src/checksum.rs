//! Internet checksum calculation.
#[cfg(all(not(feature = "remove_checksum"), kani))]
mod verification;

/// Reduces a `u64` to a `u16` via one's complement addition and converts the result to big endian if required
#[cfg(not(feature = "remove_checksum"))]
#[inline]
pub(crate) fn finalize_checksum(checksum: u64) -> u16 {
    let (mut checksum, carry) = ((checksum >> 32) as u32).overflowing_add(checksum as u32);
    checksum += u32::from(carry);

    let (mut checksum, carry) = ((checksum >> 16) as u16).overflowing_add(checksum as u16);
    checksum += u16::from(carry);

    !checksum.to_be()
}

/// Calculates the internet checksum for buffers up to and including 64 bytes.
///
/// # Panics
///
/// Panics if the `buf` length is longer than 64 bytes.
///
/// # Examples
/// ```
/// # use mutnet::checksum::internet_checksum_up_to_64_bytes;
/// let buffer = [0xFF, 10];
/// assert_eq!(0xF5, internet_checksum_up_to_64_bytes(&buffer));
/// ```
#[cfg(not(feature = "remove_checksum"))]
#[inline]
pub fn internet_checksum_up_to_64_bytes(buf: &[u8]) -> u16 {
    assert!(buf.len() <= 64);
    let checksum = checksum_match_64_bytes(buf);

    finalize_checksum(checksum)
}

#[cfg(feature = "remove_checksum")]
/// Used for layer verification, with actual checksum calculation, the proofs do not finish.
#[inline]
pub fn internet_checksum_up_to_64_bytes(_buf: &[u8]) -> u16 {
    0
}

/// Calculates the intermediary internet checksum for the provided `buf` via the method described in
/// <https://www.ietf.org/rfc/rfc1071.txt> without finalizing the checksum.
///
/// This method can be used to calculate parts of a checksum (e.g. the TCP pseudo header).
/// Use [`internet_checksum`] to use the intermediary in a checksum calculation.
///
/// # Panics
/// Panics if:
/// - the `CHUNK_SIZE` is smaller than four.
/// - the `CHUNK_SIZE` is larger than 64.
/// - the `CHUNK_SIZE` is not divisible by 4.
///
/// # Examples
/// ```
/// # use mutnet::checksum::{internet_checksum_intermediary, internet_checksum};
/// let buffer1 = [0xFF, 10];
/// let buffer2 = [0xAA, 10];
/// let intermediary = internet_checksum_intermediary::<4>(&buffer1);
/// assert_eq!(0x56ea, internet_checksum::<4>(intermediary, &buffer2));
/// ```
#[cfg(not(feature = "remove_checksum"))]
#[inline]
pub fn internet_checksum_intermediary<const CHUNK_SIZE: usize>(buf: &[u8]) -> u64 {
    assert!(CHUNK_SIZE <= 64);
    assert!(CHUNK_SIZE >= 4);
    assert_eq!(CHUNK_SIZE % 4, 0);

    let buf_iterator = buf.chunks_exact(CHUNK_SIZE);
    let buf_remainder = buf_iterator.remainder();
    let mut checksum = buf_iterator.fold(0, |mut acc, buf_part| {
        for chunk in 0..CHUNK_SIZE / 4 {
            acc += u64::from(u32::from_ne_bytes(
                buf_part[chunk * 4..chunk * 4 + 4].try_into().unwrap(),
            ));
        }

        acc
    });
    checksum += checksum_match_64_bytes(buf_remainder);
    checksum
}

#[cfg(feature = "remove_checksum")]
/// Used for layer verification, with actual checksum calculation, the proofs do not finish.
#[inline]
pub fn internet_checksum_intermediary<const CHUNK_SIZE: usize>(_buf: &[u8]) -> u64 {
    0
}

/// Calculates the internet checksum for the provided `buf` via the method described in <https://www.ietf.org/rfc/rfc1071.txt>.
///
/// If a part of the checksum was computed via [`internet_checksum_intermediary`], the intermediary
/// can be provided via `checksum_part`.
///
/// The size of the chunk processes in one loop iteration can be configured via `CHUNK_SIZE`.
/// Micro-benchmarks showed four to be a good general choice for varied buffer lengths.
/// If you only deal with very similar lengths of buffers, it may be beneficial to benchmark your
/// specific case.
///
/// # Panics
/// Panics if:
/// - the `CHUNK_SIZE` is smaller than four.
/// - the `CHUNK_SIZE` is larger than 64.
/// - the `CHUNK_SIZE` is not divisible by 4.
///
/// # Examples
/// ```
/// # use mutnet::checksum::{internet_checksum_intermediary, internet_checksum};
/// let buffer = [0xFF, 10];
/// assert_eq!(0xF5, internet_checksum::<4>(0, &buffer));
/// ```
#[cfg(not(feature = "remove_checksum"))]
#[inline]
pub fn internet_checksum<const CHUNK_SIZE: usize>(mut checksum_part: u64, buf: &[u8]) -> u16 {
    checksum_part += internet_checksum_intermediary::<CHUNK_SIZE>(buf);
    finalize_checksum(checksum_part)
}

#[cfg(feature = "remove_checksum")]
/// Used for layer verification, with actual checksum calculation, the proofs do not finish.
#[inline]
pub fn internet_checksum<const CHUNK_SIZE: usize>(_checksum_part: u64, _buf: &[u8]) -> u16 {
    0
}

/// Matches the length of the provided `buf` up to and including 64 bytes of length and calculates
/// the checksum without loop.
#[cfg(not(feature = "remove_checksum"))]
#[inline]
pub(crate) fn checksum_match_64_bytes(buf: &[u8]) -> u64 {
    let mut checksum = 0;
    match buf.len() {
        1 => {
            checksum += u64::from(u16::from_ne_bytes([buf[0], 0]));
        }
        2 => {
            checksum += u64::from(u16::from_ne_bytes(buf[0..2].try_into().unwrap()));
        }
        3 => {
            checksum += u64::from(u16::from_ne_bytes(buf[0..2].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[2], 0]));
        }
        4 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
        }
        5 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[4], 0]));
        }
        6 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[4..6].try_into().unwrap()));
        }
        7 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[4..6].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[6], 0]));
        }
        8 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
        }
        9 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[8], 0]));
        }
        10 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[8..10].try_into().unwrap()));
        }
        11 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[8..10].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[10], 0]));
        }
        12 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
        }
        13 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[12], 0]));
        }
        14 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[12..14].try_into().unwrap()));
        }
        15 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[12..14].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[14], 0]));
        }
        16 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
        }
        17 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[16], 0]));
        }
        18 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[16..18].try_into().unwrap()));
        }
        19 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[16..18].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[18], 0]));
        }
        20 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
        }
        21 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[20], 0]));
        }
        22 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[20..22].try_into().unwrap()));
        }
        23 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[20..22].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[22], 0]));
        }
        24 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
        }
        25 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[24], 0]));
        }
        26 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[24..26].try_into().unwrap()));
        }
        27 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[24..26].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[26], 0]));
        }
        28 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
        }
        29 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[28], 0]));
        }
        30 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[28..30].try_into().unwrap()));
        }
        31 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[28..30].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[30], 0]));
        }
        32 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
        }
        33 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[32], 0]));
        }
        34 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[32..34].try_into().unwrap()));
        }
        35 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[32..34].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[34], 0]));
        }
        36 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
        }
        37 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[36], 0]));
        }
        38 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[36..38].try_into().unwrap()));
        }
        39 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[36..38].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[38], 0]));
        }
        40 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
        }
        41 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[40], 0]));
        }
        42 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[40..42].try_into().unwrap()));
        }
        43 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[40..42].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[42], 0]));
        }
        44 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
        }
        45 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[44], 0]));
        }
        46 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[44..46].try_into().unwrap()));
        }
        47 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[44..46].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[46], 0]));
        }
        48 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
        }
        49 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[48], 0]));
        }
        50 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[48..50].try_into().unwrap()));
        }
        51 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[48..50].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[50], 0]));
        }
        52 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[48..52].try_into().unwrap()));
        }
        53 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[48..52].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[52], 0]));
        }
        54 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[48..52].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[52..54].try_into().unwrap()));
        }
        55 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[48..52].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[52..54].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[54], 0]));
        }
        56 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[48..52].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[52..56].try_into().unwrap()));
        }
        57 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[48..52].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[52..56].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[56], 0]));
        }
        58 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[48..52].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[52..56].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[56..58].try_into().unwrap()));
        }
        59 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[48..52].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[52..56].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[56..58].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[58], 0]));
        }
        60 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[48..52].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[52..56].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[56..60].try_into().unwrap()));
        }
        61 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[48..52].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[52..56].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[56..60].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[60], 0]));
        }
        62 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[48..52].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[52..56].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[56..60].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[60..62].try_into().unwrap()));
        }
        63 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[48..52].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[52..56].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[56..60].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes(buf[60..62].try_into().unwrap()));
            checksum += u64::from(u16::from_ne_bytes([buf[62], 0]));
        }
        64 => {
            checksum += u64::from(u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[8..12].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[12..16].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[16..20].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[20..24].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[24..28].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[28..32].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[32..36].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[36..40].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[40..44].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[44..48].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[48..52].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[52..56].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[56..60].try_into().unwrap()));
            checksum += u64::from(u32::from_ne_bytes(buf[60..64].try_into().unwrap()));
        }
        _ => {}
    }
    checksum
}

#[cfg(test)]
mod tests {
    use crate::checksum::internet_checksum;

    #[rustfmt::skip]
    #[allow(clippy::unusual_byte_groupings)]
    static CHECK_CHECKSUM: &[u8] = &[
        // Version & IHL
        0x45,
        // DSCP & ECN
        0b001010_00,
        // Total length
        0x00, 0x14,
        // Identification
        0x12, 0x34,
        // Flags & Fragment offset
        0x00, 0x00,
        // TTL
        0x01,
        // Protocol
        0x06,
        // Header Checksum
        0xA9, 0x86,
        // Source
        0x7f, 0x00, 0x00, 0x1,
        // Destination
        0x7f, 0x00, 0x00, 0x1,
    ];

    #[rustfmt::skip]
    #[allow(clippy::unusual_byte_groupings)]
    static CALC_CHECKSUM: &[u8] = &[
        // Version & IHL
        0x45,
        // DSCP & ECN
        0b001010_00,
        // Total length
        0x00, 0x14,
        // Identification
        0x12, 0x34,
        // Flags & Fragment offset
        0x00, 0x00,
        // TTL
        0x01,
        // Protocol
        0x06,
        // Header Checksum
        0x00, 0x00,
        // Source
        0x7f, 0x00, 0x00, 0x1,
        // Destination
        0x7f, 0x00, 0x00, 0x1,
    ];

    static BYTES_550: &[u8; 550] = &[0xFF; 550];
    static BYTES_1500: &[u8; 1500] = &[0xFF; 1500];

    #[test]
    fn test_checksum() {
        assert_eq!(internet_checksum::<8>(0, CHECK_CHECKSUM), 0);
        assert_eq!(internet_checksum::<8>(0, CALC_CHECKSUM), 0xA986);
    }

    #[test]
    fn test_checksum_odd() {
        assert_eq!(internet_checksum::<8>(0, &[0xFA_u8.to_le()]), !0xFA00);
        assert_eq!(
            internet_checksum::<8>(0, &[0xFA_u8.to_le(), 0xFA_u8.to_le(), 0xFA_u8.to_le()]),
            !0xF4FB
        );
    }

    #[test]
    fn test_checksum_550() {
        assert_eq!(internet_checksum::<8>(0, BYTES_550), 0);
    }

    #[test]
    fn test_checksum_1500() {
        assert_eq!(internet_checksum::<8>(0, BYTES_1500), 0);
    }
}
