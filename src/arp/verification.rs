use super::*;
use crate::data_buffer::traits::BufferIntoInner;
use crate::ethernet::Eth;

const SLICE_LENGTH: usize = 100;
const HEADROOM: usize = SLICE_LENGTH + 10;

#[kani::proof]
fn get_arp_proof() {
    let vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(to_test) = DataBuffer::<_, Arp<Eth>>::new_from_lower(to_test) {
            let _ = to_test.arp_hardware_type();
            let _ = to_test.arp_protocol_type();
            let _ = to_test.arp_typed_protocol_type();
            let _ = to_test.arp_operation_code();
            let _ = to_test.arp_typed_operation_code();
            let _ = to_test.arp_hardware_address_length();
            let _ = to_test.arp_protocol_address_length();
            let _ = to_test.arp_sender_hardware_address();
            let _ = to_test.arp_sender_protocol_address();
            let _ = to_test.arp_target_hardware_address();
            let _ = to_test.arp_target_protocol_address();
        }
    }
}

#[kani::proof]
fn arp_set_operation_code_proof() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(mut to_test) = DataBuffer::<_, Arp<Eth>>::new_from_lower(to_test) {
            to_test.arp_set_operation_code(kani::any());
            let _ = DataBuffer::<_, Arp<Eth>>::new_from_lower(
                DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), headroom).unwrap(),
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn arp_set_sender_hardware_address_proof() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(mut to_test) = DataBuffer::<_, Arp<Eth>>::new_from_lower(to_test) {
            to_test.arp_set_sender_hardware_address(&kani::any());
            let _ = DataBuffer::<_, Arp<Eth>>::new_from_lower(
                DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), headroom).unwrap(),
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn arp_set_sender_protocol_address_proof() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(mut to_test) = DataBuffer::<_, Arp<Eth>>::new_from_lower(to_test) {
            to_test.arp_set_sender_protocol_address(&kani::any());
            let _ = DataBuffer::<_, Arp<Eth>>::new_from_lower(
                DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), headroom).unwrap(),
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn arp_set_target_hardware_address_proof() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(mut to_test) = DataBuffer::<_, Arp<Eth>>::new_from_lower(to_test) {
            to_test.arp_set_target_hardware_address(&kani::any());
            let _ = DataBuffer::<_, Arp<Eth>>::new_from_lower(
                DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), headroom).unwrap(),
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn arp_set_target_protocol_address_proof() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(mut to_test) = DataBuffer::<_, Arp<Eth>>::new_from_lower(to_test) {
            to_test.arp_set_target_protocol_address(&kani::any());
            let _ = DataBuffer::<_, Arp<Eth>>::new_from_lower(
                DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), headroom).unwrap(),
            )
            .unwrap();
        }
    }
}
