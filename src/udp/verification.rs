use super::*;
use crate::data_buffer::traits::BufferIntoInner;
use crate::ethernet::Eth;
use crate::ipv6::Ipv6Methods;

const SLICE_LENGTH: usize = 100;
const HEADROOM: usize = SLICE_LENGTH + 10;
const EXTENDED_SLICE_LENGTH: usize = 150;
const EXTENDED_HEADROOM: usize = EXTENDED_SLICE_LENGTH + 10;
const CHECKSUM_IPV4: bool = true;
const CHECKSUM_UDP: bool = true;

#[kani::proof]
fn get_udp_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::new_from_lower(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Udp<Ipv4<Eth>>>::new_from_lower(to_test, CHECKSUM_UDP)
            {
                let _ = to_test.udp_source_port();
                let _ = to_test.udp_destination_port();
                let _ = to_test.udp_length();
                let _ = to_test.udp_checksum();
                let _ = to_test.udp_calculate_checksum();
                let _ = to_test.payload();
                let _ = to_test.payload_mut();
                let _ = to_test.payload_length();
            }
        }
    }
}

#[kani::proof]
fn get_udp_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Udp<Ipv6<Eth>>>::new_from_lower(to_test, CHECKSUM_UDP)
            {
                let _ = to_test.udp_source_port();
                let _ = to_test.udp_destination_port();
                let _ = to_test.udp_length();
                let _ = to_test.udp_checksum();
                let _ = to_test.udp_calculate_checksum();
                let _ = to_test.payload();
                let _ = to_test.payload_mut();
                let _ = to_test.payload_length();
            }
        }
    }
}

#[kani::proof]
fn set_udp_source_port_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::new_from_lower(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Udp<Ipv4<Eth>>>::new_from_lower(to_test, CHECKSUM_UDP)
            {
                to_test.set_udp_source_port(kani::any());
                let _ = DataBuffer::<_, Udp<Ipv4<Eth>>>::new_from_lower(
                    DataBuffer::<_, Ipv4<Eth>>::new_from_lower(
                        DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), any_headroom)
                            .unwrap(),
                        CHECKSUM_IPV4,
                    )
                    .unwrap(),
                    CHECKSUM_UDP,
                )
                .unwrap();
            }
        }
    }
}

#[kani::proof]
fn set_udp_source_port_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Udp<Ipv6<Eth>>>::new_from_lower(to_test, CHECKSUM_UDP)
            {
                to_test.set_udp_source_port(kani::any());
                let _ = DataBuffer::<_, Udp<Ipv6<Eth>>>::new_from_lower(
                    DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                        DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), any_headroom)
                            .unwrap(),
                    )
                    .unwrap(),
                    CHECKSUM_UDP,
                )
                .unwrap();
            }
        }
    }
}

#[kani::proof]
fn set_udp_destination_port_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::new_from_lower(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Udp<Ipv4<Eth>>>::new_from_lower(to_test, CHECKSUM_UDP)
            {
                to_test.set_udp_destination_port(kani::any());
                let _ = DataBuffer::<_, Udp<Ipv4<Eth>>>::new_from_lower(
                    DataBuffer::<_, Ipv4<Eth>>::new_from_lower(
                        DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), any_headroom)
                            .unwrap(),
                        CHECKSUM_IPV4,
                    )
                    .unwrap(),
                    CHECKSUM_UDP,
                )
                .unwrap();
            }
        }
    }
}

#[kani::proof]
fn set_udp_destination_port_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Udp<Ipv6<Eth>>>::new_from_lower(to_test, CHECKSUM_UDP)
            {
                to_test.set_udp_destination_port(kani::any());
                let _ = DataBuffer::<_, Udp<Ipv6<Eth>>>::new_from_lower(
                    DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                        DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), any_headroom)
                            .unwrap(),
                    )
                    .unwrap(),
                    CHECKSUM_UDP,
                )
                .unwrap();
            }
        }
    }
}

#[kani::proof]
fn set_udp_length_ipv4_proof() {
    let mut any_array: [u8; EXTENDED_SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= EXTENDED_SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= EXTENDED_HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::new_from_lower(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Udp<Ipv4<Eth>>>::new_from_lower(to_test, CHECKSUM_UDP)
            {
                let old_udp_length_usize = usize::from(to_test.udp_length());
                let new_udp_length = kani::any();
                let new_udp_length_usize = usize::from(new_udp_length);

                let data_length = to_test.data_length();
                let ipv4_total_length = usize::from(to_test.ipv4_total_length());

                if to_test.set_udp_length(new_udp_length).is_ok() {
                    assert!(new_udp_length >= 8);

                    match old_udp_length_usize.cmp(&new_udp_length_usize) {
                        core::cmp::Ordering::Less => {
                            let difference = new_udp_length_usize - old_udp_length_usize;
                            assert_eq!(
                                old_udp_length_usize + difference,
                                usize::from(to_test.udp_length())
                            );
                        }
                        core::cmp::Ordering::Equal => {
                            assert_eq!(old_udp_length_usize, usize::from(to_test.udp_length()));
                        }
                        core::cmp::Ordering::Greater => {
                            let difference = old_udp_length_usize - new_udp_length_usize;
                            assert_eq!(
                                old_udp_length_usize - difference,
                                usize::from(to_test.udp_length())
                            );
                        }
                    }
                    assert_eq!(
                        new_udp_length_usize + to_test.header_length(Layer::Ipv4),
                        usize::from(to_test.ipv4_total_length())
                    );
                    assert_eq!(
                        to_test.header_start_offset(Layer::Udp) + new_udp_length_usize,
                        to_test.data_length()
                    );
                } else {
                    assert_eq!(data_length, to_test.data_length());
                    assert_eq!(ipv4_total_length, usize::from(to_test.ipv4_total_length()));
                    assert_eq!(old_udp_length_usize, usize::from(to_test.udp_length()));
                }
                let _ = DataBuffer::<_, Udp<Ipv4<Eth>>>::new_from_lower(
                    DataBuffer::<_, Ipv4<Eth>>::new_from_lower(
                        DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), any_headroom)
                            .unwrap(),
                        CHECKSUM_IPV4,
                    )
                    .unwrap(),
                    CHECKSUM_UDP,
                )
                .unwrap();
            }
        }
    }
}

#[kani::proof]
fn set_udp_length_ipv6_proof() {
    let mut any_array: [u8; EXTENDED_SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= EXTENDED_SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= EXTENDED_HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Udp<Ipv6<Eth>>>::new_from_lower(to_test, CHECKSUM_UDP)
            {
                let old_udp_length_usize = usize::from(to_test.udp_length());
                let new_udp_length = kani::any();
                let new_udp_length_usize = usize::from(new_udp_length);

                let data_length = to_test.data_length();
                let ipv6_payload_length = usize::from(to_test.ipv6_payload_length());

                if to_test.set_udp_length(new_udp_length).is_ok() {
                    assert!(new_udp_length >= 8);

                    match old_udp_length_usize.cmp(&new_udp_length_usize) {
                        core::cmp::Ordering::Less => {
                            let difference = new_udp_length_usize - old_udp_length_usize;
                            assert_eq!(
                                old_udp_length_usize + difference,
                                usize::from(to_test.udp_length())
                            );
                        }
                        core::cmp::Ordering::Equal => {
                            assert_eq!(old_udp_length_usize, usize::from(to_test.udp_length()));
                        }
                        core::cmp::Ordering::Greater => {
                            let difference = old_udp_length_usize - new_udp_length_usize;
                            assert_eq!(
                                old_udp_length_usize - difference,
                                usize::from(to_test.udp_length())
                            );
                        }
                    }
                    assert_eq!(
                        new_udp_length_usize,
                        usize::from(to_test.ipv6_payload_length())
                    );
                    assert_eq!(
                        to_test.header_start_offset(Layer::Udp) + new_udp_length_usize,
                        to_test.data_length()
                    );
                } else {
                    assert_eq!(data_length, to_test.data_length());
                    assert_eq!(
                        ipv6_payload_length,
                        usize::from(to_test.ipv6_payload_length())
                    );
                    assert_eq!(old_udp_length_usize, usize::from(to_test.udp_length()));
                }
                let _ = DataBuffer::<_, Udp<Ipv6<Eth>>>::new_from_lower(
                    DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                        DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), any_headroom)
                            .unwrap(),
                    )
                    .unwrap(),
                    CHECKSUM_UDP,
                )
                .unwrap();
            }
        }
    }
}

#[kani::proof]
fn set_udp_checksum_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::new_from_lower(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Udp<Ipv4<Eth>>>::new_from_lower(to_test, CHECKSUM_UDP)
            {
                to_test.set_udp_checksum(kani::any());
                let _ = DataBuffer::<_, Udp<Ipv4<Eth>>>::new_from_lower(
                    DataBuffer::<_, Ipv4<Eth>>::new_from_lower(
                        DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), any_headroom)
                            .unwrap(),
                        CHECKSUM_IPV4,
                    )
                    .unwrap(),
                    CHECKSUM_UDP,
                )
                .unwrap();
            }
        }
    }
}

#[kani::proof]
fn set_udp_checksum_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Udp<Ipv6<Eth>>>::new_from_lower(to_test, CHECKSUM_UDP)
            {
                to_test.set_udp_checksum(kani::any());
                let _ = DataBuffer::<_, Udp<Ipv6<Eth>>>::new_from_lower(
                    DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                        DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), any_headroom)
                            .unwrap(),
                    )
                    .unwrap(),
                    CHECKSUM_UDP,
                )
                .unwrap();
            }
        }
    }
}

#[kani::proof]
fn update_udp_checksum_ipv4_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv4<Eth>>::new_from_lower(to_test, CHECKSUM_IPV4) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Udp<Ipv4<Eth>>>::new_from_lower(to_test, CHECKSUM_UDP)
            {
                to_test.update_udp_checksum();
                let _ = DataBuffer::<_, Udp<Ipv4<Eth>>>::new_from_lower(
                    DataBuffer::<_, Ipv4<Eth>>::new_from_lower(
                        DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), any_headroom)
                            .unwrap(),
                        CHECKSUM_IPV4,
                    )
                    .unwrap(),
                    CHECKSUM_UDP,
                )
                .unwrap();
            }
        }
    }
}

#[kani::proof]
fn update_udp_checksum_ipv6_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::new(any_slice, any_headroom) {
        if let Ok(to_test) = DataBuffer::<_, Ipv6<Eth>>::new_from_lower(to_test) {
            if let Ok(mut to_test) =
                DataBuffer::<_, Udp<Ipv6<Eth>>>::new_from_lower(to_test, CHECKSUM_UDP)
            {
                to_test.update_udp_checksum();
                let _ = DataBuffer::<_, Udp<Ipv6<Eth>>>::new_from_lower(
                    DataBuffer::<_, Ipv6<Eth>>::new_from_lower(
                        DataBuffer::<_, Eth>::new(to_test.buffer_into_inner(), any_headroom)
                            .unwrap(),
                    )
                    .unwrap(),
                    CHECKSUM_UDP,
                )
                .unwrap();
            }
        }
    }
}
