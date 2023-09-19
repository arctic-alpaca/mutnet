use super::*;
use crate::data_buffer::traits::BufferIntoInner;
use crate::ethernet::Eth;
use crate::tcp::Tcp;

const SLICE_LENGTH: usize = 100;
const HEADROOM: usize = SLICE_LENGTH + 10;
const CHECKSUM_TCP: bool = true;

#[kani::proof]
fn get_ipv6_proof() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(mut to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            let _ = to_test.ipv6_version();
            let _ = to_test.ipv6_traffic_class();
            let _ = to_test.ipv6_flow_label();
            let _ = to_test.ipv6_payload_length();
            let _ = to_test.ipv6_next_header();
            let _ = to_test.ipv6_typed_next_header();
            let _ = to_test.ipv6_hop_limit();
            let _ = to_test.ipv6_source();
            let _ = to_test.ipv6_destination();
            let _ = to_test.payload();
            let _ = to_test.payload_mut();
            let _ = to_test.payload_length();
        }
    }
}

#[kani::proof]
fn set_ipv6_traffic_class_proof() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(mut to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            to_test.set_ipv6_traffic_class(kani::any());
            let _ = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), headroom).unwrap(),
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn set_ipv6_flow_label_proof() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(mut to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            to_test.set_ipv6_flow_label(kani::any());
            let _ = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), headroom).unwrap(),
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn set_ipv6_payload_length_proof() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(mut to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            let _ = to_test.set_ipv6_payload_length(kani::any());
            let _ = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), headroom).unwrap(),
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn set_ipv6_payload_length_proof_complete() {
    let mut vec = kani::vec::any_vec::<u8, 150>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::new_from_lower(to_test, CHECKSUM_TCP)
            {
                let old_ipv6_payload_length_usize = usize::from(to_test.ipv6_payload_length());
                let new_ipv6_payload_length = kani::any();
                let new_ipv6_payload_length_usize = usize::from(new_ipv6_payload_length);

                let internal_headroom = to_test.headroom();
                let data_length = to_test.data_length();
                let eth_header_start_offset = to_test.header_start_offset(Layer::EthernetII);
                let eth_header_length = to_test.header_length(Layer::EthernetII);
                let ipv6_header_start_offset = to_test.header_start_offset(Layer::Ipv6);
                let ipv6_header_length = to_test.header_length(Layer::Ipv6);
                let tcp_header_start_offset = to_test.header_start_offset(Layer::Tcp);
                let tcp_header_length = to_test.header_length(Layer::Tcp);

                if to_test
                    .set_ipv6_payload_length(new_ipv6_payload_length)
                    .is_ok()
                {
                    match old_ipv6_payload_length_usize.cmp(&new_ipv6_payload_length_usize) {
                        core::cmp::Ordering::Less => {
                            let difference =
                                new_ipv6_payload_length_usize - old_ipv6_payload_length_usize;
                            assert_eq!(data_length + difference, to_test.data_length());
                        }
                        core::cmp::Ordering::Equal => {
                            assert_eq!(data_length, to_test.data_length());
                        }
                        core::cmp::Ordering::Greater => {
                            let difference =
                                old_ipv6_payload_length_usize - new_ipv6_payload_length_usize;
                            assert_eq!(data_length - difference, to_test.data_length());
                        }
                    }
                } else {
                    assert_eq!(data_length, to_test.data_length());
                }

                assert_eq!(internal_headroom, to_test.headroom());
                assert_eq!(
                    eth_header_start_offset,
                    to_test.header_start_offset(Layer::EthernetII)
                );
                assert_eq!(eth_header_length, to_test.header_length(Layer::EthernetII));
                assert_eq!(
                    ipv6_header_start_offset,
                    to_test.header_start_offset(Layer::Ipv6)
                );
                assert_eq!(ipv6_header_length, to_test.header_length(Layer::Ipv6));
                assert_eq!(
                    tcp_header_start_offset,
                    to_test.header_start_offset(Layer::Tcp)
                );
                assert_eq!(tcp_header_length, to_test.header_length(Layer::Tcp));

                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::new_from_lower(
                    DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                        DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), headroom).unwrap(),
                    )
                    .unwrap(),
                    CHECKSUM_TCP,
                )
                .unwrap();
            }
        }
    }
}

#[kani::proof]
fn set_ipv6_next_header_proof() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(mut to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            to_test.set_ipv6_next_header(kani::any());
            let _ = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), headroom).unwrap(),
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn set_ipv6_hop_limit_proof() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(mut to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            to_test.set_ipv6_hop_limit(kani::any());
            let _ = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), headroom).unwrap(),
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn set_ipv6_source_proof() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(mut to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            to_test.set_ipv6_source(kani::any());
            let _ = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), headroom).unwrap(),
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn set_ipv6_destination_proof() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(mut to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            to_test.set_ipv6_destination(kani::any());
            let _ = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), headroom).unwrap(),
            )
            .unwrap();
        }
    }
}
