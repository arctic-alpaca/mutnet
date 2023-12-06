use super::*;
use crate::data_buffer::traits::BufferIntoInner;
use crate::ethernet::Eth;
use crate::ipv4::Ipv4Methods;
use crate::ipv6::Ipv6Methods;

const SLICE_LENGTH: usize = 100;
const HEADROOM: usize = SLICE_LENGTH + 10;
const EXTENDED_SLICE_LENGTH: usize = 150;
const EXTENDED_HEADROOM: usize = EXTENDED_SLICE_LENGTH + 10;
const CHECKSUM_IPV4: bool = true;
const CHECKSUM_TCP: bool = true;

#[kani::proof]
fn get_tcp_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                let _ = to_test.tcp_source_port();
                let _ = to_test.tcp_destination_port();
                let _ = to_test.tcp_sequence_number();
                let _ = to_test.tcp_acknowledgment_number();
                let _ = to_test.tcp_data_offset();
                let _ = to_test.tcp_reserved_bits();
                let _ = to_test.tcp_flags();
                let _ = to_test.tcp_congestion_window_reduced_flag();
                let _ = to_test.tcp_ecn_echo_flag();
                let _ = to_test.tcp_urgent_pointer_flag();
                let _ = to_test.tcp_acknowledgement_flag();
                let _ = to_test.tcp_push_flag();
                let _ = to_test.tcp_reset_flag();
                let _ = to_test.tcp_synchronize_flag();
                let _ = to_test.tcp_fin_flag();
                let _ = to_test.tcp_window_size();
                let _ = to_test.tcp_checksum();
                let _ = to_test.tcp_urgent_pointer();
                let _ = to_test.tcp_options();
                let _ = to_test.tcp_options_mut();
                let _ = to_test.tcp_calculate_checksum();
                let _ = to_test.payload();
                let _ = to_test.payload_mut();
                let _ = to_test.payload_length();
            }
        }
    }
}

#[kani::proof]
fn get_tcp_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                let _ = to_test.tcp_source_port();
                let _ = to_test.tcp_destination_port();
                let _ = to_test.tcp_sequence_number();
                let _ = to_test.tcp_acknowledgment_number();
                let _ = to_test.tcp_data_offset();
                let _ = to_test.tcp_reserved_bits();
                let _ = to_test.tcp_flags();
                let _ = to_test.tcp_congestion_window_reduced_flag();
                let _ = to_test.tcp_ecn_echo_flag();
                let _ = to_test.tcp_urgent_pointer_flag();
                let _ = to_test.tcp_acknowledgement_flag();
                let _ = to_test.tcp_push_flag();
                let _ = to_test.tcp_reset_flag();
                let _ = to_test.tcp_synchronize_flag();
                let _ = to_test.tcp_fin_flag();
                let _ = to_test.tcp_window_size();
                let _ = to_test.tcp_checksum();
                let _ = to_test.tcp_urgent_pointer();
                let _ = to_test.tcp_options();
                let _ = to_test.tcp_options_mut();
                let _ = to_test.tcp_calculate_checksum();
                let _ = to_test.payload();
                let _ = to_test.payload_mut();
                let _ = to_test.payload_length();
            }
        }
    }
}

#[kani::proof]
fn set_tcp_source_port_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_source_port(kani::any());
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
fn set_tcp_source_port_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_source_port(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_destination_port_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_destination_port(kani::any());
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
fn set_tcp_destination_port_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_destination_port(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_sequence_number_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_sequence_number(kani::any());
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
fn set_tcp_sequence_number_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_sequence_number(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_acknowledgement_number_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_acknowledgement_number(kani::any());
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
fn set_tcp_acknowledgement_number_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_acknowledgement_number(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_data_offset_ipv4_proof() {
    let mut any_array: [u8; EXTENDED_SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= EXTENDED_SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let mut any_headroom = kani::any_where(|i| *i <= EXTENDED_HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                let old_tcp_data_offset_bytes = usize::from(to_test.tcp_data_offset()) * 4;
                let new_tcp_data_offset = kani::any();
                let new_tcp_data_offset_bytes_usize = usize::from(new_tcp_data_offset) * 4;

                let internal_headroom = to_test.headroom_internal();
                let data_length = to_test.data_length_internal();
                let eth_header_start_offset = to_test.header_start_offset(Layer::EthernetII);
                let eth_header_length = to_test.header_length(Layer::EthernetII);
                let ipv4_header_start_offset = to_test.header_start_offset(Layer::Ipv4);
                let ipv4_header_length = to_test.header_length(Layer::Ipv4);
                let ipv4_total_length = usize::from(to_test.ipv4_total_length());
                let tcp_header_start_offset = to_test.header_start_offset(Layer::Tcp);
                let tcp_header_length = to_test.header_length(Layer::Tcp);

                if to_test.set_tcp_data_offset(new_tcp_data_offset).is_ok() {
                    match old_tcp_data_offset_bytes.cmp(&new_tcp_data_offset_bytes_usize) {
                        core::cmp::Ordering::Less => {
                            let difference =
                                new_tcp_data_offset_bytes_usize - old_tcp_data_offset_bytes;
                            any_headroom -= difference;
                            assert_eq!(internal_headroom - difference, to_test.headroom_internal());
                            assert_eq!(data_length + difference, to_test.data_length_internal());
                            assert_eq!(
                                tcp_header_length + difference,
                                to_test.header_length(Layer::Tcp)
                            );
                            assert_eq!(
                                ipv4_total_length + difference,
                                usize::from(to_test.ipv4_total_length())
                            );
                        }
                        core::cmp::Ordering::Equal => {
                            assert_eq!(internal_headroom, to_test.headroom_internal());
                            assert_eq!(data_length, to_test.data_length_internal());
                            assert_eq!(tcp_header_length, to_test.header_length(Layer::Tcp));
                            assert_eq!(ipv4_total_length, usize::from(to_test.ipv4_total_length()));
                        }
                        core::cmp::Ordering::Greater => {
                            let difference =
                                old_tcp_data_offset_bytes - new_tcp_data_offset_bytes_usize;
                            any_headroom += difference;
                            assert_eq!(internal_headroom + difference, to_test.headroom_internal());
                            assert_eq!(data_length - difference, to_test.data_length_internal());
                            assert_eq!(
                                tcp_header_length - difference,
                                to_test.header_length(Layer::Tcp)
                            );
                            assert_eq!(
                                ipv4_total_length - difference,
                                usize::from(to_test.ipv4_total_length())
                            );
                        }
                    }
                } else {
                    assert_eq!(internal_headroom, to_test.headroom_internal());
                    assert_eq!(data_length, to_test.data_length_internal());
                    assert_eq!(tcp_header_length, to_test.header_length(Layer::Tcp));
                    assert_eq!(ipv4_total_length, usize::from(to_test.ipv4_total_length()));
                }
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
fn set_tcp_data_offset_ipv6_proof() {
    let mut any_array: [u8; EXTENDED_SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= EXTENDED_SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let mut any_headroom = kani::any_where(|i| *i <= EXTENDED_HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                let old_tcp_data_offset_bytes = usize::from(to_test.tcp_data_offset()) * 4;
                let new_tcp_data_offset = kani::any();
                let new_tcp_data_offset_bytes_usize = usize::from(new_tcp_data_offset) * 4;

                let internal_headroom = to_test.headroom_internal();
                let data_length = to_test.data_length_internal();
                let eth_header_start_offset = to_test.header_start_offset(Layer::EthernetII);
                let eth_header_length = to_test.header_length(Layer::EthernetII);
                let ipv6_header_start_offset = to_test.header_start_offset(Layer::Ipv6);
                let ipv6_header_length = to_test.header_length(Layer::Ipv6);
                let ipv6_payload_length = usize::from(to_test.ipv6_payload_length());
                let tcp_header_start_offset = to_test.header_start_offset(Layer::Tcp);
                let tcp_header_length = to_test.header_length(Layer::Tcp);

                if to_test.set_tcp_data_offset(new_tcp_data_offset).is_ok() {
                    match old_tcp_data_offset_bytes.cmp(&new_tcp_data_offset_bytes_usize) {
                        core::cmp::Ordering::Less => {
                            let difference =
                                new_tcp_data_offset_bytes_usize - old_tcp_data_offset_bytes;
                            any_headroom -= difference;
                            assert_eq!(internal_headroom - difference, to_test.headroom_internal());
                            assert_eq!(data_length + difference, to_test.data_length_internal());
                            assert_eq!(
                                tcp_header_length + difference,
                                to_test.header_length(Layer::Tcp)
                            );
                            assert_eq!(
                                ipv6_payload_length + difference,
                                usize::from(to_test.ipv6_payload_length())
                            );
                        }
                        core::cmp::Ordering::Equal => {
                            assert_eq!(internal_headroom, to_test.headroom_internal());
                            assert_eq!(data_length, to_test.data_length_internal());
                            assert_eq!(
                                eth_header_start_offset,
                                to_test.header_start_offset(Layer::EthernetII)
                            );
                            assert_eq!(tcp_header_length, to_test.header_length(Layer::Tcp));
                            assert_eq!(
                                ipv6_payload_length,
                                usize::from(to_test.ipv6_payload_length())
                            );
                        }
                        core::cmp::Ordering::Greater => {
                            let difference =
                                old_tcp_data_offset_bytes - new_tcp_data_offset_bytes_usize;
                            any_headroom += difference;
                            assert_eq!(internal_headroom + difference, to_test.headroom_internal());
                            assert_eq!(data_length - difference, to_test.data_length_internal());
                            assert_eq!(
                                tcp_header_length - difference,
                                to_test.header_length(Layer::Tcp)
                            );
                            assert_eq!(
                                ipv6_payload_length - difference,
                                usize::from(to_test.ipv6_payload_length())
                            );
                        }
                    }
                } else {
                    assert_eq!(internal_headroom, to_test.headroom_internal());
                    assert_eq!(data_length, to_test.data_length_internal());
                    assert_eq!(tcp_header_length, to_test.header_length(Layer::Tcp));
                    assert_eq!(
                        ipv6_payload_length,
                        usize::from(to_test.ipv6_payload_length())
                    );
                }
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
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_reserved_bits_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_reserved_bits(kani::any());
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
fn set_tcp_reserved_bits_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_reserved_bits(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_flags_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_flags(kani::any());
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
fn set_tcp_flags_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_flags(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_congestion_window_reduced_flag_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_congestion_window_reduced_flag(kani::any());
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
fn set_tcp_congestion_window_reduced_flag_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_congestion_window_reduced_flag(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_ecn_echo_flag_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_ecn_echo_flag(kani::any());
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
fn set_tcp_ecn_echo_flag_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_ecn_echo_flag(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_urgent_pointer_flag_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_urgent_pointer_flag(kani::any());
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
fn set_tcp_urgent_pointer_flag_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_urgent_pointer_flag(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_acknowledgement_flag_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_acknowledgement_flag(kani::any());
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
fn set_tcp_acknowledgement_flag_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_acknowledgement_flag(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_push_flag_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_push_flag(kani::any());
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
fn set_tcp_push_flag_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_push_flag(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_reset_flag_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_reset_flag(kani::any());
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
fn set_tcp_reset_flag_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_reset_flag(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_synchronize_flag_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_synchronize_flag(kani::any());
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
fn set_tcp_synchronize_flag_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_synchronize_flag(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_fin_flag_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_fin_flag(kani::any());
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
fn set_tcp_fin_flag_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_fin_flag(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_window_size_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_window_size(kani::any());
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
fn set_tcp_window_size_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_window_size(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_checksum_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_checksum(kani::any());
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
fn set_tcp_checksum_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_checksum(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn set_tcp_urgent_pointer_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_urgent_pointer(kani::any());
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
fn set_tcp_urgent_pointer_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.set_tcp_urgent_pointer(kani::any());
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
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
fn update_tcp_checksum_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.update_tcp_checksum();
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
fn update_tcp_checksum_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(to_test, CHECKSUM_TCP)
            {
                to_test.update_tcp_checksum();
                let _ = DataBuffer::<_, Tcp<Ipv6<Eth>>>::parse_tcp_layer(
                    DataBuffer::<_, Ipv6<Eth>>::parse_ipv6_layer(
                        DataBuffer::<_, Eth>::parse_ethernet_layer(
                            to_test.buffer_into_inner(),
                            any_headroom,
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    CHECKSUM_TCP,
                )
                .unwrap();
            }
        }
    }
}
