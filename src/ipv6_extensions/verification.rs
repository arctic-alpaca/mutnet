use crate::data_buffer::traits::BufferIntoInner;
use crate::ethernet::Eth;
use crate::ipv6::{Ipv6, Ipv6Methods};
use crate::tcp::Tcp;

use super::*;

const SLICE_LENGTH: usize = 100;
const HEADROOM: usize = SLICE_LENGTH + 10;
const EXTENDED_SLICE_LENGTH: usize = 150;
const EXTENDED_HEADROOM: usize = EXTENDED_SLICE_LENGTH + 10;
const MAX_EXTENSIONS: usize = 5;

#[kani::proof]
#[kani::unwind(6)]
fn get_ipv6_ext_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(next_header) = to_test.ipv6_next_header().try_into() {
                if let Ok((mut to_test, _has_fragment)) = DataBuffer::<
                    _,
                    Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>,
                >::parse_ipv6_extensions_layer(
                    to_test, next_header
                ) {
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
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(first_extension) = to_test.ipv6_next_header().try_into() {
                if let Ok((mut to_test, _has_fragment)) = DataBuffer::<
                    _,
                    Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>,
                >::parse_ipv6_extensions_layer(
                    to_test, first_extension
                ) {
                    let next_header = kani::any();
                    kani::assume(next_header as u8 != Ipv6ExtensionType::HopByHop as u8);
                    kani::assume(next_header as u8 != Ipv6ExtensionType::DestinationOptions as u8);
                    kani::assume(next_header as u8 != Ipv6ExtensionType::Fragment as u8);
                    kani::assume(next_header as u8 != Ipv6ExtensionType::Routing as u8);
                    let _ = to_test.set_ipv6_ext_next_header(next_header);

                    let to_test = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                    let _ =
                        DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::parse_ipv6_extensions_layer(
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
    let mut any_array: [u8; EXTENDED_SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= EXTENDED_SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let mut any_headroom = kani::any_where(|i| *i <= EXTENDED_HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(first_extension) = to_test.ipv6_next_header().try_into() {
                if let Ok((to_test, has_fragment)) = DataBuffer::<
                    _,
                    Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>,
                >::parse_ipv6_extensions_layer(
                    to_test, first_extension
                ) {
                    if !has_fragment {
                        if let Ok(mut to_test) = DataBuffer::<
                            _,
                            Tcp<Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>,
                        >::parse_tcp_layer(
                            to_test, true
                        ) {
                            let selected_ext = kani::any();

                            // Extension exists
                            if let Ok(current_ext_length_in_bytes) =
                                to_test.ipv6_ext_length_in_bytes(selected_ext)
                            {
                                let new_ext_length = kani::any();
                                let new_ext_length_in_bytes = (usize::from(new_ext_length) + 1) * 8;

                                let internal_headroom = to_test.headroom_internal();
                                let data_length = to_test.data_length_internal();
                                let eth_header_start_offset =
                                    to_test.header_start_offset(Layer::EthernetII);
                                let eth_header_length = to_test.header_length(Layer::EthernetII);
                                let ipv6_header_start_offset =
                                    to_test.header_start_offset(Layer::Ipv6);
                                let ipv6_header_length = to_test.header_length(Layer::Ipv6);
                                let ipv6_ext_header_start_offset =
                                    to_test.header_start_offset(Layer::Ipv6Ext);
                                let ipv6_ext_header_length = to_test.header_length(Layer::Ipv6Ext);
                                let ipv6_payload_length =
                                    usize::from(to_test.ipv6_payload_length());
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
                                            any_headroom -= difference;
                                            assert_eq!(
                                                data_length + difference,
                                                to_test.data_length_internal()
                                            );
                                            assert_eq!(
                                                internal_headroom - difference,
                                                to_test.headroom_internal()
                                            );
                                            assert_eq!(
                                                ipv6_ext_header_length + difference,
                                                to_test.header_length(Layer::Ipv6Ext)
                                            );
                                            assert_eq!(
                                                tcp_header_start_offset + difference,
                                                to_test.header_start_offset(Layer::Tcp)
                                            );
                                            assert_eq!(
                                                ipv6_payload_length + difference,
                                                usize::from(to_test.ipv6_payload_length())
                                            );
                                        }
                                        core::cmp::Ordering::Equal => {
                                            assert_eq!(data_length, to_test.data_length_internal());
                                            assert_eq!(
                                                internal_headroom,
                                                to_test.headroom_internal()
                                            );
                                            assert_eq!(
                                                ipv6_ext_header_length,
                                                to_test.header_length(Layer::Ipv6Ext)
                                            );
                                            assert_eq!(
                                                tcp_header_start_offset,
                                                to_test.header_start_offset(Layer::Tcp)
                                            );
                                            assert_eq!(
                                                ipv6_payload_length,
                                                usize::from(to_test.ipv6_payload_length())
                                            );
                                        }
                                        core::cmp::Ordering::Greater => {
                                            let difference = current_ext_length_in_bytes
                                                - new_ext_length_in_bytes;
                                            any_headroom += difference;
                                            assert_eq!(
                                                data_length - difference,
                                                to_test.data_length_internal()
                                            );
                                            assert_eq!(
                                                internal_headroom + difference,
                                                to_test.headroom_internal()
                                            );
                                            assert_eq!(
                                                ipv6_ext_header_length - difference,
                                                to_test.header_length(Layer::Ipv6Ext)
                                            );
                                            assert_eq!(
                                                tcp_header_start_offset - difference,
                                                to_test.header_start_offset(Layer::Tcp)
                                            );
                                            assert_eq!(
                                                ipv6_payload_length - difference,
                                                usize::from(to_test.ipv6_payload_length())
                                            );
                                        }
                                    }
                                } else {
                                    assert_eq!(data_length, to_test.data_length_internal());
                                    assert_eq!(internal_headroom, to_test.headroom_internal());
                                    assert_eq!(
                                        ipv6_ext_header_length,
                                        to_test.header_length(Layer::Ipv6Ext)
                                    );
                                    assert_eq!(
                                        tcp_header_start_offset,
                                        to_test.header_start_offset(Layer::Tcp)
                                    );
                                    assert_eq!(
                                        ipv6_payload_length,
                                        usize::from(to_test.ipv6_payload_length())
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

                                let eth = DataBuffer::<_, Eth>::parse_ethernet_layer(
                                    to_test.buffer_into_inner(),
                                    any_headroom,
                                )
                                .unwrap();
                                let ipv6 =
                                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(eth).unwrap();
                                let (ipv6_exts, _has_fragment) = DataBuffer::<
                                    _,
                                    Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>,
                                >::parse_ipv6_extensions_layer(
                                    ipv6, first_extension
                                )
                                .unwrap();
                                let _ = DataBuffer::<
                                    _,
                                    Tcp<Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>,
                                >::parse_tcp_layer(
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
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(first_extension) = to_test.ipv6_next_header().try_into() {
                if let Ok((mut to_test, _has_fragment)) = DataBuffer::<
                    _,
                    Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>,
                >::parse_ipv6_extensions_layer(
                    to_test, first_extension
                ) {
                    let _ = to_test.set_ipv6_ext_routing_type(kani::any(), kani::any());
                    let _ =
                        DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::parse_ipv6_extensions_layer(
                            DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                                DataBuffer::<_, Eth>::parse_ethernet_layer(
                                    to_test.buffer_into_inner(),
                                    any_headroom,
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
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(first_extension) = to_test.ipv6_next_header().try_into() {
                if let Ok((mut to_test, _has_fragment)) = DataBuffer::<
                    _,
                    Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>,
                >::parse_ipv6_extensions_layer(
                    to_test, first_extension
                ) {
                    let _ = to_test.set_ipv6_ext_segments_left(kani::any(), kani::any());
                    let _ =
                        DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::parse_ipv6_extensions_layer(
                            DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                                DataBuffer::<_, Eth>::parse_ethernet_layer(
                                    to_test.buffer_into_inner(),
                                    any_headroom,
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
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(first_extension) = to_test.ipv6_next_header().try_into() {
                if let Ok((mut to_test, _has_fragment)) = DataBuffer::<
                    _,
                    Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>,
                >::parse_ipv6_extensions_layer(
                    to_test, first_extension
                ) {
                    let _ = to_test.set_ipv6_ext_fragment_offset(kani::any(), kani::any());
                    let _ =
                        DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::parse_ipv6_extensions_layer(
                            DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                                DataBuffer::<_, Eth>::parse_ethernet_layer(
                                    to_test.buffer_into_inner(),
                                    any_headroom,
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
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(first_extension) = to_test.ipv6_next_header().try_into() {
                if let Ok((mut to_test, _has_fragment)) = DataBuffer::<
                    _,
                    Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>,
                >::parse_ipv6_extensions_layer(
                    to_test, first_extension
                ) {
                    let _ = to_test.set_ipv6_ext_more_fragments(kani::any(), kani::any());
                    let _ =
                        DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::parse_ipv6_extensions_layer(
                            DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                                DataBuffer::<_, Eth>::parse_ethernet_layer(
                                    to_test.buffer_into_inner(),
                                    any_headroom,
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
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(first_extension) = to_test.ipv6_next_header().try_into() {
                if let Ok((mut to_test, _has_fragment)) = DataBuffer::<
                    _,
                    Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>,
                >::parse_ipv6_extensions_layer(
                    to_test, first_extension
                ) {
                    let _ = to_test.set_ipv6_ext_fragment_identification(kani::any(), kani::any());
                    let _ =
                        DataBuffer::<_, Ipv6Extensions<Ipv6<Eth>, MAX_EXTENSIONS>>::parse_ipv6_extensions_layer(
                            DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                                DataBuffer::<_, Eth>::parse_ethernet_layer(
                                    to_test.buffer_into_inner(),
                                    any_headroom,
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
