use super::*;

#[kani::proof]
fn finalize_checksum_proof() {
    finalize_checksum(kani::any());
}

#[kani::proof]
fn internet_checksum_up_to_64_bytes_proof() {
    let vec = kani::vec::any_vec::<u8, 64>();
    let slice = vec.as_slice();
    internet_checksum_up_to_64_bytes(slice);
}

#[kani::proof]
#[kani::unwind(20)]
fn internet_checksum_intermediary_proof() {
    let vec = kani::vec::any_vec::<u8, 64>();
    let slice = vec.as_slice();
    internet_checksum_intermediary::<4>(slice);
}

#[kani::proof]
#[kani::unwind(20)]
fn internet_checksum_variable_chunks_proof() {
    let vec = kani::vec::any_vec::<u8, 64>();
    let slice = vec.as_slice();
    internet_checksum::<4>(0, slice);
}
