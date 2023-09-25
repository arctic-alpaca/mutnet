use super::*;

const CHECKSUM_INPUT_LENGTH: usize = 64;

#[kani::proof]
fn finalize_checksum_proof() {
    finalize_checksum(kani::any());
}

#[kani::proof]
fn internet_checksum_up_to_64_bytes_proof() {
    let mut any_array: [u8; CHECKSUM_INPUT_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= CHECKSUM_INPUT_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    internet_checksum_up_to_64_bytes(any_slice);
}

#[kani::proof]
#[kani::unwind(20)]
fn internet_checksum_intermediary_proof() {
    let mut any_array: [u8; CHECKSUM_INPUT_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= CHECKSUM_INPUT_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    internet_checksum_intermediary::<4>(any_slice);
}

#[kani::proof]
#[kani::unwind(20)]
fn internet_checksum_variable_chunks_proof() {
    let mut any_array: [u8; CHECKSUM_INPUT_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= CHECKSUM_INPUT_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    internet_checksum::<4>(0, any_slice);
}
