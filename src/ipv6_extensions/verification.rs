use super::*;
use crate::data_buffer::traits::BufferIntoInner;
use crate::ethernet::Eth;
use crate::ipv6::{Ipv6, Ipv6Methods};
use crate::tcp::Tcp;

const SLICE_LENGTH: usize = 100;
const HEADROOM: usize = SLICE_LENGTH + 10;
const MAX_EXTENSIONS: usize = 5;

#[kani::proof]
#[kani::unwind(6)]
fn get_ipv6_ext_proof() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            if let Ok(next_header) = to_test.ipv6_next_header().try_into() {
                if let Ok((mut to_test, _has_fragment)) =
                    DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::new_from_lower(
                        to_test,
                        next_header,
                    )
                {
                    let _ = to_test.ipv6_ext_amount();
                    let _ = to_test.ipv6_extensions();
                    let _ = to_test.ipv6_ext_next_header();
                    let _ = to_test.ipv6_ext_typed_next_header();
                    let _ = to_test.ipv6_ext_per_extension_next_header(kani::any());
                    let _ = to_test.ipv6_ext_per_extension_typed_next_header(kani::any());
                    let _ = to_test.ipv6_ext_length(kani::any());
                    let _ = to_test.ipv6_ext_length_in_bytes(kani::any());
                    let _ = to_test.ipv6_ext_data(kani::any());
                    let _ = to_test.ipv6_ext_data_mut(kani::any());
                    let _ = to_test.ipv6_ext_routing_type(kani::any());
                    let _ = to_test.ipv6_ext_segments_left(kani::any());
                    let _ = to_test.ipv6_ext_fragment_offset(kani::any());
                    let _ = to_test.ipv6_ext_more_fragments(kani::any());
                    let _ = to_test.ipv6_ext_fragment_identification(kani::any());
                    let _ = to_test.payload();
                    let _ = to_test.payload_mut();
                    let _ = to_test.payload_length();
                }
            }
        }
    }
}

#[kani::proof]
#[kani::unwind(6)]
fn set_ipv6_ext_next_header() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            if let Ok(first_extension) = to_test.ipv6_next_header().try_into() {
                if let Ok((mut to_test, _has_fragment)) =
                    DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::new_from_lower(
                        to_test,
                        first_extension,
                    )
                {
                    let next_header = kani::any();
                    kani::assume(next_header as u8 != Ipv6Extension::HopByHop as u8);
                    kani::assume(next_header as u8 != Ipv6Extension::DestinationOptions as u8);
                    kani::assume(next_header as u8 != Ipv6Extension::Fragment as u8);
                    kani::assume(next_header as u8 != Ipv6Extension::Routing as u8);
                    let _ = to_test.set_ipv6_ext_next_header(next_header);

                    let to_test = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                        DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), headroom)
                            .unwrap(),
                    )
                    .unwrap();
                    let _ =
                        DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::new_from_lower(
                            to_test,
                            first_extension,
                        )
                        .unwrap();
                }
            }
        }
    }
}

#[kani::unwind(6)]
#[kani::proof]
fn set_ipv6_ext_length_complete() {
    let mut vec = kani::vec::any_vec::<u8, 150>();
    let slice = vec.as_mut_slice();
    let mut headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            if let Ok(first_extension) = to_test.ipv6_next_header().try_into() {
                if let Ok((to_test, has_fragment)) =
                    DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::new_from_lower(
                        to_test,
                        first_extension,
                    )
                {
                    if !has_fragment {
                        if let Ok(mut to_test) = DataBuffer::<
                            _,
                            Tcp<Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>,
                        >::new_from_lower(
                            to_test, true
                        ) {
                            let selected_ext = kani::any();

                            // Extension exists
                            if let Ok(current_ext_length_in_bytes) =
                                to_test.ipv6_ext_length_in_bytes(selected_ext)
                            {
                                let new_ext_length = kani::any();
                                let new_ext_length_in_bytes = (usize::from(new_ext_length) + 1) * 8;

                                let internal_headroom = to_test.headroom();
                                let data_length = to_test.data_length();
                                let eth_header_start_offset =
                                    to_test.header_start_offset(Layer::EthernetII);
                                let eth_header_length = to_test.header_length(Layer::EthernetII);
                                let ipv6_header_start_offset =
                                    to_test.header_start_offset(Layer::Ipv6);
                                let ipv6_header_length = to_test.header_length(Layer::Ipv6);
                                let ipv6_ext_header_start_offset =
                                    to_test.header_start_offset(Layer::Ipv6Ext);
                                let ipv6_ext_header_length = to_test.header_length(Layer::Ipv6Ext);
                                let tcp_header_start_offset =
                                    to_test.header_start_offset(Layer::Tcp);
                                let tcp_header_length = to_test.header_length(Layer::Tcp);
                                if to_test
                                    .set_ipv6_ext_length(new_ext_length, selected_ext)
                                    .is_ok()
                                {
                                    match current_ext_length_in_bytes.cmp(&new_ext_length_in_bytes)
                                    {
                                        core::cmp::Ordering::Less => {
                                            let difference = new_ext_length_in_bytes
                                                - current_ext_length_in_bytes;
                                            headroom -= difference;
                                            assert_eq!(
                                                data_length + difference,
                                                to_test.data_length()
                                            );
                                            assert_eq!(
                                                internal_headroom - difference,
                                                to_test.headroom()
                                            );
                                            assert_eq!(
                                                ipv6_ext_header_length + difference,
                                                to_test.header_length(Layer::Ipv6Ext)
                                            );
                                            assert_eq!(
                                                tcp_header_start_offset + difference,
                                                to_test.header_start_offset(Layer::Tcp)
                                            );
                                        }
                                        core::cmp::Ordering::Equal => {
                                            assert_eq!(data_length, to_test.data_length());
                                            assert_eq!(
                                                internal_headroom,
                                                to_test.headroom()
                                            );
                                            assert_eq!(
                                                ipv6_ext_header_length,
                                                to_test.header_length(Layer::Ipv6Ext)
                                            );
                                            assert_eq!(
                                                tcp_header_start_offset,
                                                to_test.header_start_offset(Layer::Tcp)
                                            );
                                        }
                                        core::cmp::Ordering::Greater => {
                                            let difference = current_ext_length_in_bytes
                                                - new_ext_length_in_bytes;
                                            headroom += difference;
                                            assert_eq!(
                                                data_length - difference,
                                                to_test.data_length()
                                            );
                                            assert_eq!(
                                                internal_headroom + difference,
                                                to_test.headroom()
                                            );
                                            assert_eq!(
                                                ipv6_ext_header_length - difference,
                                                to_test.header_length(Layer::Ipv6Ext)
                                            );
                                            assert_eq!(
                                                tcp_header_start_offset - difference,
                                                to_test.header_start_offset(Layer::Tcp)
                                            );
                                        }
                                    }
                                } else {
                                    assert_eq!(data_length, to_test.data_length());
                                    assert_eq!(
                                        internal_headroom,
                                        to_test.headroom()
                                    );
                                    assert_eq!(
                                        ipv6_ext_header_length,
                                        to_test.header_length(Layer::Ipv6Ext)
                                    );
                                    assert_eq!(
                                        tcp_header_start_offset,
                                        to_test.header_start_offset(Layer::Tcp)
                                    );
                                }
                                assert_eq!(
                                    eth_header_start_offset,
                                    to_test.header_start_offset(Layer::EthernetII)
                                );
                                assert_eq!(
                                    eth_header_length,
                                    to_test.header_length(Layer::EthernetII)
                                );
                                assert_eq!(
                                    ipv6_header_start_offset,
                                    to_test.header_start_offset(Layer::Ipv6)
                                );
                                assert_eq!(ipv6_header_length, to_test.header_length(Layer::Ipv6));
                                assert_eq!(
                                    ipv6_ext_header_start_offset,
                                    to_test.header_start_offset(Layer::Ipv6Ext)
                                );
                                assert_eq!(tcp_header_length, to_test.header_length(Layer::Tcp));

                                let eth = DataBuffer::<_, Eth>::new(
                                    to_test.buffer_into_inner(),
                                    headroom,
                                )
                                .unwrap();
                                let ipv6 = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(eth).unwrap();
                                let (ipv6_exts, _has_fragment) = DataBuffer::<
                                    _,
                                    Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>,
                                >::new_from_lower(
                                    ipv6, first_extension
                                )
                                .unwrap();
                                let _ = DataBuffer::<
                                    _,
                                    Tcp<Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>,
                                >::new_from_lower(
                                    ipv6_exts, true
                                )
                                .unwrap();
                            }
                        }
                    }
                }
            }
        }
    }
}

#[kani::proof]
#[kani::unwind(6)]
fn set_ipv6_ext_routing_type() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            if let Ok(first_extension) = to_test.ipv6_next_header().try_into() {
                if let Ok((mut to_test, _has_fragment)) =
                    DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::new_from_lower(
                        to_test,
                        first_extension,
                    )
                {
                    let _ = to_test.set_ipv6_ext_routing_type(kani::any(), kani::any());
                    let _ =
                        DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::new_from_lower(
                            DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                                DataBuffer::<_, Eth>::new(
                                    to_test.buffer_into_inner(),
                                    headroom,
                                )
                                .unwrap(),
                            )
                            .unwrap(),
                            first_extension,
                        )
                        .unwrap();
                }
            }
        }
    }
}

#[kani::proof]
#[kani::unwind(6)]
fn set_ipv6_ext_segments_left() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            if let Ok(first_extension) = to_test.ipv6_next_header().try_into() {
                if let Ok((mut to_test, _has_fragment)) =
                    DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::new_from_lower(
                        to_test,
                        first_extension,
                    )
                {
                    let _ = to_test.set_ipv6_ext_segments_left(kani::any(), kani::any());
                    let _ =
                        DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::new_from_lower(
                            DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                                DataBuffer::<_, Eth>::new(
                                    to_test.buffer_into_inner(),
                                    headroom,
                                )
                                .unwrap(),
                            )
                            .unwrap(),
                            first_extension,
                        )
                        .unwrap();
                }
            }
        }
    }
}

#[kani::proof]
#[kani::unwind(6)]
fn set_ipv6_ext_fragment_offset() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            if let Ok(first_extension) = to_test.ipv6_next_header().try_into() {
                if let Ok((mut to_test, _has_fragment)) =
                    DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::new_from_lower(
                        to_test,
                        first_extension,
                    )
                {
                    let _ = to_test.set_ipv6_ext_fragment_offset(kani::any(), kani::any());
                    let _ =
                        DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::new_from_lower(
                            DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                                DataBuffer::<_, Eth>::new(
                                    to_test.buffer_into_inner(),
                                    headroom,
                                )
                                .unwrap(),
                            )
                            .unwrap(),
                            first_extension,
                        )
                        .unwrap();
                }
            }
        }
    }
}

#[kani::proof]
#[kani::unwind(6)]
fn set_ipv6_ext_more_fragments() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            if let Ok(first_extension) = to_test.ipv6_next_header().try_into() {
                if let Ok((mut to_test, _has_fragment)) =
                    DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::new_from_lower(
                        to_test,
                        first_extension,
                    )
                {
                    let _ = to_test.set_ipv6_ext_more_fragments(kani::any(), kani::any());
                    let _ =
                        DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::new_from_lower(
                            DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                                DataBuffer::<_, Eth>::new(
                                    to_test.buffer_into_inner(),
                                    headroom,
                                )
                                .unwrap(),
                            )
                            .unwrap(),
                            first_extension,
                        )
                        .unwrap();
                }
            }
        }
    }
}

#[kani::proof]
#[kani::unwind(6)]
fn set_ipv6_ext_fragment_identification() {
    let mut vec = kani::vec::any_vec::<u8, SLICE_LENGTH>();
    let slice = vec.as_mut_slice();
    let headroom = kani::any();
    kani::assume(headroom < HEADROOM);
    if let Ok(to_test) = DataBuffer::<_, Eth>::new(slice, headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            if let Ok(first_extension) = to_test.ipv6_next_header().try_into() {
                if let Ok((mut to_test, _has_fragment)) =
                    DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::new_from_lower(
                        to_test,
                        first_extension,
                    )
                {
                    let _ = to_test.set_ipv6_ext_fragment_identification(kani::any(), kani::any());
                    let _ =
                        DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::new_from_lower(
                            DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                                DataBuffer::<_, Eth>::new(
                                    to_test.buffer_into_inner(),
                                    headroom,
                                )
                                .unwrap(),
                            )
                            .unwrap(),
                            first_extension,
                        )
                        .unwrap();
                }
            }
        }
    }
}
