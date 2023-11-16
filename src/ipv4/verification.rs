use super::*;
use crate::data_buffer::traits::BufferIntoInner;
use crate::ethernet::Eth;
use crate::tcp::Tcp;

const SLICE_LENGTH: usize = 80;
const HEADROOM: usize = SLICE_LENGTH + 10;

const EXTENDED_SLICE_LENGTH: usize = 150;
const EXTENDED_HEADROOM: usize = EXTENDED_SLICE_LENGTH + 10;

const CHECKSUM_IPV4: bool = false;
const CHECKSUM_TCP: bool = false;

#[kani::proof]
fn get_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(mut to_test) =
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4)
        {
            let _ = to_test.ipv4_version();
            let _ = to_test.ipv4_ihl();
            let _ = to_test.ipv4_dscp();
            let _ = to_test.ipv4_typed_dscp();
            let _ = to_test.ipv4_ecn();
            let _ = to_test.ipv4_typed_ecn();
            let _ = to_test.ipv4_total_length();
            let _ = to_test.ipv4_identification();
            let _ = to_test.ipv4_flags();
            let _ = to_test.ipv4_evil_flag();
            let _ = to_test.ipv4_dont_fragment_flag();
            let _ = to_test.ipv4_more_fragments_flag();
            let _ = to_test.ipv4_fragment_offset();
            let _ = to_test.ipv4_time_to_live();
            let _ = to_test.ipv4_protocol();
            let _ = to_test.ipv4_typed_protocol();
            let _ = to_test.ipv4_header_checksum();
            let _ = to_test.ipv4_calculate_checksum();
            let _ = to_test.ipv4_source();
            let _ = to_test.ipv4_destination();
            let _ = to_test.ipv4_options();
            let _ = to_test.ipv4_options_mut();
            let _ = to_test.ipv4_payload_length();
            let _ = to_test.payload();
            let _ = to_test.payload_mut();
            let _ = to_test.payload_length();
        }
    }
}

#[kani::proof]
fn set_ipv4_ihl_proof_complete() {
    let mut any_array: [u8; EXTENDED_SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= EXTENDED_SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let mut any_headroom = kani::any_where(|i| *i <= EXTENDED_HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                let old_ipv4_ihl_bytes_usize = usize::from(to_test.ipv4_ihl()) * 4;
                let new_ipv4_ihl = kani::any();
                let new_ipv4_ihl_bytes_usize = usize::from(new_ipv4_ihl) * 4;

                let internal_headroom = to_test.headroom_internal();
                let data_length = to_test.data_length();
                let eth_header_start_offset = to_test.header_start_offset(Layer::EthernetII);
                let eth_header_length = to_test.header_length(Layer::EthernetII);
                let ipv4_header_start_offset = to_test.header_start_offset(Layer::Ipv4);
                let ipv4_header_length = to_test.header_length(Layer::Ipv4);
                let tcp_header_start_offset = to_test.header_start_offset(Layer::Tcp);
                let tcp_header_length = to_test.header_length(Layer::Tcp);

                if to_test.set_ipv4_ihl(new_ipv4_ihl).is_ok() {
                    match old_ipv4_ihl_bytes_usize.cmp(&new_ipv4_ihl_bytes_usize) {
                        core::cmp::Ordering::Less => {
                            let difference = new_ipv4_ihl_bytes_usize - old_ipv4_ihl_bytes_usize;
                            any_headroom -= difference;
                            assert_eq!(internal_headroom - difference, to_test.headroom_internal());
                            assert_eq!(data_length + difference, to_test.data_length());
                            assert_eq!(
                                eth_header_start_offset,
                                to_test.header_start_offset(Layer::EthernetII)
                            );
                            assert_eq!(eth_header_length, to_test.header_length(Layer::EthernetII));
                            assert_eq!(
                                ipv4_header_start_offset,
                                to_test.header_start_offset(Layer::Ipv4)
                            );
                            assert_eq!(
                                ipv4_header_length + difference,
                                to_test.header_length(Layer::Ipv4)
                            );
                            assert_eq!(
                                tcp_header_start_offset + difference,
                                to_test.header_start_offset(Layer::Tcp)
                            );
                            assert_eq!(tcp_header_length, to_test.header_length(Layer::Tcp));
                        }
                        core::cmp::Ordering::Equal => {
                            assert_eq!(internal_headroom, to_test.headroom_internal());
                            assert_eq!(data_length, to_test.data_length());
                            assert_eq!(
                                eth_header_start_offset,
                                to_test.header_start_offset(Layer::EthernetII)
                            );
                            assert_eq!(eth_header_length, to_test.header_length(Layer::EthernetII));
                            assert_eq!(
                                ipv4_header_start_offset,
                                to_test.header_start_offset(Layer::Ipv4)
                            );
                            assert_eq!(ipv4_header_length, to_test.header_length(Layer::Ipv4));
                            assert_eq!(
                                tcp_header_start_offset,
                                to_test.header_start_offset(Layer::Tcp)
                            );
                            assert_eq!(tcp_header_length, to_test.header_length(Layer::Tcp));
                        }
                        core::cmp::Ordering::Greater => {
                            let difference = old_ipv4_ihl_bytes_usize - new_ipv4_ihl_bytes_usize;
                            any_headroom += difference;
                            assert_eq!(internal_headroom + difference, to_test.headroom_internal());
                            assert_eq!(data_length - difference, to_test.data_length());
                            assert_eq!(
                                eth_header_start_offset,
                                to_test.header_start_offset(Layer::EthernetII)
                            );
                            assert_eq!(eth_header_length, to_test.header_length(Layer::EthernetII));
                            assert_eq!(
                                ipv4_header_start_offset,
                                to_test.header_start_offset(Layer::Ipv4)
                            );
                            assert_eq!(
                                ipv4_header_length - difference,
                                to_test.header_length(Layer::Ipv4)
                            );
                            assert_eq!(
                                tcp_header_start_offset - difference,
                                to_test.header_start_offset(Layer::Tcp)
                            );
                            assert_eq!(tcp_header_length, to_test.header_length(Layer::Tcp));
                        }
                    }
                    let _ = DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(
                        DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                            DataBuffer::<_, Eth>::parse_ethernet_layer(
                                to_test.buffer_into_inner(),
                                any_headroom,
                            )
                            .unwrap(),
                            CHECKSUM_IPV4,
                        )
                        .unwrap(),
                        CHECKSUM_TCP,
                    )
                    .unwrap();
                }
            }
        }
    }
}

#[kani::proof]
fn ipv4_set_dscp_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(mut to_test) =
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4)
        {
            let _ = to_test.set_ipv4_dscp(kani::any());
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                CHECKSUM_IPV4,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn ipv4_set_ecn_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(mut to_test) =
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4)
        {
            let _ = to_test.set_ipv4_ecn(kani::any());
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                CHECKSUM_IPV4,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn ipv4_set_total_length_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(mut to_test) =
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4)
        {
            let _ = to_test.set_ipv4_total_length(kani::any());
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                CHECKSUM_IPV4,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn ipv4_set_total_length_proof_complete() {
    let mut any_array: [u8; EXTENDED_SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= EXTENDED_SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= EXTENDED_HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                let old_ipv4_total_length_usize = usize::from(to_test.ipv4_total_length());
                let new_ipv4_total_length = kani::any();
                let new_ipv4_total_length_usize = usize::from(new_ipv4_total_length);

                let internal_headroom = to_test.headroom_internal();
                let data_length = to_test.data_length();
                let eth_header_start_offset = to_test.header_start_offset(Layer::EthernetII);
                let eth_header_length = to_test.header_length(Layer::EthernetII);
                let ipv4_header_start_offset = to_test.header_start_offset(Layer::Ipv4);
                let ipv4_header_length = to_test.header_length(Layer::Ipv4);
                let tcp_header_start_offset = to_test.header_start_offset(Layer::Tcp);
                let tcp_header_length = to_test.header_length(Layer::Tcp);

                if to_test.set_ipv4_total_length(new_ipv4_total_length).is_ok() {
                    match old_ipv4_total_length_usize.cmp(&new_ipv4_total_length_usize) {
                        core::cmp::Ordering::Less => {
                            let difference =
                                new_ipv4_total_length_usize - old_ipv4_total_length_usize;
                            assert_eq!(data_length + difference, to_test.data_length());
                        }
                        core::cmp::Ordering::Equal => {
                            assert_eq!(data_length, to_test.data_length());
                        }
                        core::cmp::Ordering::Greater => {
                            let difference =
                                old_ipv4_total_length_usize - new_ipv4_total_length_usize;
                            assert_eq!(data_length - difference, to_test.data_length());
                        }
                    }
                } else {
                    assert_eq!(data_length, to_test.data_length());
                }
                assert_eq!(internal_headroom, to_test.headroom_internal());
                assert_eq!(
                    eth_header_start_offset,
                    to_test.header_start_offset(Layer::EthernetII)
                );
                assert_eq!(eth_header_length, to_test.header_length(Layer::EthernetII));
                assert_eq!(
                    ipv4_header_start_offset,
                    to_test.header_start_offset(Layer::Ipv4)
                );
                assert_eq!(ipv4_header_length, to_test.header_length(Layer::Ipv4));
                assert_eq!(
                    tcp_header_start_offset,
                    to_test.header_start_offset(Layer::Tcp)
                );
                assert_eq!(tcp_header_length, to_test.header_length(Layer::Tcp));
                let _ = DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
                        CHECKSUM_IPV4,
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
fn ipv4_set_identification_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(mut to_test) =
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4)
        {
            let _ = to_test.set_ipv4_identification(kani::any());
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                CHECKSUM_IPV4,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn ipv4_set_flags_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(mut to_test) =
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4)
        {
            let _ = to_test.set_ipv4_flags(kani::any());
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                CHECKSUM_IPV4,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn set_ipv4_evil_flag_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(mut to_test) =
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4)
        {
            let _ = to_test.set_ipv4_evil_flag(kani::any());
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                CHECKSUM_IPV4,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn set_ipv4_dont_fragment_flag_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(mut to_test) =
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4)
        {
            let _ = to_test.set_ipv4_dont_fragment_flag(kani::any());
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                CHECKSUM_IPV4,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn set_ipv4_more_fragments_flag_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(mut to_test) =
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4)
        {
            let _ = to_test.set_ipv4_more_fragments_flag(kani::any());
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                CHECKSUM_IPV4,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn ipv4_set_fragment_offset_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(mut to_test) =
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4)
        {
            let _ = to_test.set_ipv4_fragment_offset(kani::any());
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                CHECKSUM_IPV4,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn ipv4_set_time_to_live_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(mut to_test) =
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4)
        {
            let _ = to_test.set_ipv4_time_to_live(kani::any());
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                CHECKSUM_IPV4,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn ipv4_set_protocol_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(mut to_test) =
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4)
        {
            let _ = to_test.set_ipv4_protocol(kani::any());
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                CHECKSUM_IPV4,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn ipv4_set_header_checksum_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(mut to_test) =
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4)
        {
            let _ = to_test.set_ipv4_header_checksum(kani::any());
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                CHECKSUM_IPV4,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn ipv4_update_header_checksum_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(mut to_test) =
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4)
        {
            let _ = to_test.update_ipv4_header_checksum();
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                CHECKSUM_IPV4,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn ipv4_set_source_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(mut to_test) =
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4)
        {
            let _ = to_test.set_ipv4_source(kani::any());
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                CHECKSUM_IPV4,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn ipv4_set_destination_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(mut to_test) =
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4)
        {
            let _ = to_test.set_ipv4_destination(kani::any());
            DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                CHECKSUM_IPV4,
            )
            .unwrap();
        }
    }
}
