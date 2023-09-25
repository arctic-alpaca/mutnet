use super::*;
use crate::data_buffer::traits::BufferIntoInner;

const SLICE_LENGTH: usize = 20 + 40;
const HEADROOM: usize = SLICE_LENGTH + 10;

#[kani::proof]
fn get_ethernet_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(mut to_test) = DataBuffer::<_, Eth>::new(any_slice, any_headroom) {
        let _ = to_test.ethernet_destination();
        let _ = to_test.ethernet_source();
        let _ = to_test.ethernet_ether_type();
        let _ = to_test.ethernet_typed_ether_type();
        let _ = to_test.payload();
        let _ = to_test.payload_mut();
        let _ = to_test.payload_length();
    }
}

#[kani::proof]
fn set_ethernet_destination_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(mut to_test) = DataBuffer::<_, Eth>::new(any_slice, any_headroom) {
        let _ = to_test.set_ethernet_destination(&kani::any());
        DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), any_headroom).unwrap();
    }
}

#[kani::proof]
fn set_ethernet_source_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(mut to_test) = DataBuffer::<_, Eth>::new(any_slice, any_headroom) {
        let _ = to_test.set_ethernet_source(&kani::any());
        DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), any_headroom).unwrap();
    }
}

#[kani::proof]
fn set_ethernet_ether_type_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(mut to_test) = DataBuffer::<_, Eth>::new(any_slice, any_headroom) {
        let _ = to_test.set_ethernet_ether_type(kani::any());
        DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), any_headroom).unwrap();
    }
}
