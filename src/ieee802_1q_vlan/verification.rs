use super::*;
use crate::data_buffer::traits::BufferIntoInner;
use crate::ethernet::{Eth, EthernetMethods};
use crate::ipv6::Ipv6;
use crate::tcp::Tcp;
use crate::typed_protocol_headers::constants;
use crate::typed_protocol_headers::EtherType;

const SLICE_LENGTH: usize = 60;
const HEADROOM: usize = SLICE_LENGTH + 10;

const EXTENDED_SLICE_LENGTH: usize = 150;
const EXTENDED_HEADROOM: usize = EXTENDED_SLICE_LENGTH + 10;

#[kani::proof]
fn get_ieee_802_1q_proof() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        let vlan = match to_test.ethernet_ether_type() {
            constants::CUSTOMER_TAG_802_1Q => Vlan::SingleTagged,
            constants::SERVICE_TAG_802_1Q => Vlan::DoubleTagged,
            _ => return,
        };
        if let Ok(mut to_test) =
            DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(to_test, vlan)
        {
            let _ = to_test.ieee802_1q_c_tag_control_information();
            let _ = to_test.ieee802_1q_c_tag_priority_code_point();
            let _ = to_test.ieee802_1q_c_tag_drop_eligible_indicator();
            let _ = to_test.ieee802_1q_c_tag_vlan_identifier();
            let _ = to_test.ieee802_1q_s_tag_control_information();
            let _ = to_test.ieee802_1q_s_tag_priority_code_point();
            let _ = to_test.ieee802_1q_s_tag_drop_eligible_indicator();
            let _ = to_test.ieee802_1q_s_tag_vlan_identifier();
            assert_eq!(vlan, to_test.ieee802_1q_typed_vlan());
            let _ = to_test.ieee802_1q_ether_type();
            let _ = to_test.ieee802_1q_typed_ether_type();
            let _ = to_test.payload();
            let _ = to_test.payload_mut();
            let _ = to_test.payload_length();
        }
    }
}

#[kani::proof]
fn set_ieee802_1q_c_tag_control_information() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        let vlan = match to_test.ethernet_ether_type() {
            constants::CUSTOMER_TAG_802_1Q => Vlan::SingleTagged,
            constants::SERVICE_TAG_802_1Q => Vlan::DoubleTagged,
            _ => return,
        };
        if let Ok(mut to_test) =
            DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(to_test, vlan)
        {
            let array: [u8; 2] = kani::any();
            to_test.set_ieee802_1q_c_tag_control_information(&array);
            let _ = DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                vlan,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn set_ieee802_1q_c_tag_priority_code_point() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        let vlan = match to_test.ethernet_ether_type() {
            constants::CUSTOMER_TAG_802_1Q => Vlan::SingleTagged,
            constants::SERVICE_TAG_802_1Q => Vlan::DoubleTagged,
            _ => return,
        };
        if let Ok(mut to_test) =
            DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(to_test, vlan)
        {
            to_test.set_ieee802_1q_c_tag_priority_code_point(kani::any());
            let _ = DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                vlan,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn set_ieee802_1q_c_tag_drop_eligible_indicator() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        let vlan = match to_test.ethernet_ether_type() {
            constants::CUSTOMER_TAG_802_1Q => Vlan::SingleTagged,
            constants::SERVICE_TAG_802_1Q => Vlan::DoubleTagged,
            _ => return,
        };
        if let Ok(mut to_test) =
            DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(to_test, vlan)
        {
            to_test.set_ieee802_1q_c_tag_drop_eligible_indicator(kani::any());
            let _ = DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                vlan,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn set_ieee802_1q_c_tag_vlan_identifier() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        let vlan = match to_test.ethernet_ether_type() {
            constants::CUSTOMER_TAG_802_1Q => Vlan::SingleTagged,
            constants::SERVICE_TAG_802_1Q => Vlan::DoubleTagged,
            _ => return,
        };
        if let Ok(mut to_test) =
            DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(to_test, vlan)
        {
            to_test.set_ieee802_1q_c_tag_vlan_identifier(kani::any());
            let _ = DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                vlan,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn add_or_update_ieee802_1q_s_tag() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let mut any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        let mut vlan = match to_test.ethernet_ether_type() {
            constants::CUSTOMER_TAG_802_1Q => Vlan::SingleTagged,
            constants::SERVICE_TAG_802_1Q => Vlan::DoubleTagged,
            _ => return,
        };
        if let Ok(mut to_test) =
            DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(to_test, vlan)
        {
            let array: [u8; 2] = kani::any();
            if to_test.add_or_update_ieee802_1q_s_tag(&array).is_ok() {
                if vlan == Vlan::SingleTagged {
                    any_headroom -= 4;
                    vlan = Vlan::DoubleTagged;
                }
            }
            let _ = DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                vlan,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn add_or_update_ieee802_1q_s_tag_complete() {
    let mut any_array: [u8; EXTENDED_SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= EXTENDED_SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let mut any_headroom = kani::any_where(|i| *i <= EXTENDED_HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        let mut vlan = match to_test.ethernet_ether_type() {
            constants::CUSTOMER_TAG_802_1Q => Vlan::SingleTagged,
            constants::SERVICE_TAG_802_1Q => Vlan::DoubleTagged,
            _ => return,
        };
        if let Ok(to_test) =
            DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(to_test, vlan)
        {
            if let Ok(to_test) =
                DataBuffer::<_, Ipv6<Ieee802_1QVlan<Eth>>>::parse_ipv6_layer(to_test)
            {
                if let Ok(mut to_test) =
                    DataBuffer::<_, Tcp<Ipv6<Ieee802_1QVlan<Eth>>>>::parse_tcp_layer(to_test, true)
                {
                    let internal_headroom = to_test.headroom_internal();
                    let data_length = to_test.data_length_internal();
                    let eth_header_start_offset = to_test.header_start_offset(Layer::EthernetII);
                    let eth_header_length = to_test.header_length(Layer::EthernetII);
                    let vlan_header_start_offset =
                        to_test.header_start_offset(Layer::Ieee802_1QVlan);
                    let vlan_header_length = to_test.header_length(Layer::Ieee802_1QVlan);
                    let ipv6_header_start_offset = to_test.header_start_offset(Layer::Ipv6);
                    let ipv6_header_length = to_test.header_length(Layer::Ipv6);
                    let tcp_header_start_offset = to_test.header_start_offset(Layer::Tcp);
                    let tcp_header_length = to_test.header_length(Layer::Tcp);

                    let param = kani::arbitrary::Arbitrary::any_array();
                    if to_test.add_or_update_ieee802_1q_s_tag(&param).is_ok()
                        && vlan == Vlan::SingleTagged
                    {
                        vlan = Vlan::DoubleTagged;
                        any_headroom -= 4;
                        // data start
                        assert_eq!(internal_headroom - 4, to_test.headroom_internal());
                        // data length
                        assert_eq!(data_length + 4, to_test.data_length_internal());
                        // vlan header length
                        assert_eq!(
                            vlan_header_length + 4,
                            to_test.header_length(Layer::Ieee802_1QVlan)
                        );
                        // higher layer header offset
                        assert_eq!(
                            ipv6_header_start_offset + 4,
                            to_test.header_start_offset(Layer::Ipv6)
                        );
                        assert_eq!(
                            tcp_header_start_offset + 4,
                            to_test.header_start_offset(Layer::Tcp)
                        );
                        assert_eq!(EtherType::ServiceTag as u16, to_test.ethernet_ether_type());
                    } else {
                        // data start
                        assert_eq!(internal_headroom, to_test.headroom_internal());
                        // data length
                        assert_eq!(data_length, to_test.data_length_internal());
                        // vlan header length
                        assert_eq!(
                            vlan_header_length,
                            to_test.header_length(Layer::Ieee802_1QVlan)
                        );
                        // higher layer header offset
                        assert_eq!(
                            ipv6_header_start_offset,
                            to_test.header_start_offset(Layer::Ipv6)
                        );
                        assert_eq!(
                            tcp_header_start_offset,
                            to_test.header_start_offset(Layer::Tcp)
                        );
                        match vlan {
                            Vlan::SingleTagged => {
                                assert_eq!(
                                    EtherType::CustomerTag as u16,
                                    to_test.ethernet_ether_type()
                                );
                            }
                            Vlan::DoubleTagged => {
                                assert_eq!(
                                    EtherType::ServiceTag as u16,
                                    to_test.ethernet_ether_type()
                                );
                            }
                        }
                    }
                    assert_eq!(
                        eth_header_start_offset,
                        to_test.header_start_offset(Layer::EthernetII)
                    );
                    assert_eq!(eth_header_length, to_test.header_length(Layer::EthernetII));
                    assert_eq!(
                        vlan_header_start_offset,
                        to_test.header_start_offset(Layer::Ieee802_1QVlan)
                    );
                    assert_eq!(ipv6_header_length, to_test.header_length(Layer::Ipv6));
                    assert_eq!(tcp_header_length, to_test.header_length(Layer::Tcp));

                    let eth = DataBuffer::<_, Eth>::parse_ethernet_layer(
                        to_test.buffer_into_inner(),
                        any_headroom,
                    )
                    .unwrap();
                    let vlan =
                        DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(eth, vlan)
                            .unwrap();
                    let ipv6 =
                        DataBuffer::<_, Ipv6<Ieee802_1QVlan<Eth>>>::parse_ipv6_layer(vlan).unwrap();
                    let _ = DataBuffer::<_, Tcp<Ipv6<Ieee802_1QVlan<Eth>>>>::parse_tcp_layer(
                        ipv6, true,
                    )
                    .unwrap();
                }
            }
        }
    }
}

#[kani::proof]
fn set_ieee802_1q_s_tag_priority_code_point() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        let vlan = match to_test.ethernet_ether_type() {
            constants::CUSTOMER_TAG_802_1Q => Vlan::SingleTagged,
            constants::SERVICE_TAG_802_1Q => Vlan::DoubleTagged,
            _ => return,
        };
        if let Ok(mut to_test) =
            DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(to_test, vlan)
        {
            match vlan {
                Vlan::SingleTagged => {
                    assert_eq!(
                        Err(NotDoubleTaggedError),
                        to_test.set_ieee802_1q_s_tag_priority_code_point(kani::any())
                    );
                }
                Vlan::DoubleTagged => {
                    to_test
                        .set_ieee802_1q_s_tag_priority_code_point(kani::any())
                        .unwrap();
                }
            }
            let _ = DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                vlan,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn set_ieee802_1q_s_tag_drop_eligible_indicator() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        let vlan = match to_test.ethernet_ether_type() {
            constants::CUSTOMER_TAG_802_1Q => Vlan::SingleTagged,
            constants::SERVICE_TAG_802_1Q => Vlan::DoubleTagged,
            _ => return,
        };
        if let Ok(mut to_test) =
            DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(to_test, vlan)
        {
            match vlan {
                Vlan::SingleTagged => {
                    assert_eq!(
                        Err(NotDoubleTaggedError),
                        to_test.set_ieee802_1q_s_tag_drop_eligible_indicator(kani::any())
                    );
                }
                Vlan::DoubleTagged => {
                    to_test
                        .set_ieee802_1q_s_tag_drop_eligible_indicator(kani::any())
                        .unwrap();
                }
            }
            let _ = DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                vlan,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn set_ieee802_1q_s_tag_vlan_identifier() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        let vlan = match to_test.ethernet_ether_type() {
            constants::CUSTOMER_TAG_802_1Q => Vlan::SingleTagged,
            constants::SERVICE_TAG_802_1Q => Vlan::DoubleTagged,
            _ => return,
        };
        if let Ok(mut to_test) =
            DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(to_test, vlan)
        {
            match vlan {
                Vlan::SingleTagged => {
                    assert_eq!(
                        Err(NotDoubleTaggedError),
                        to_test.set_ieee802_1q_s_tag_vlan_identifier(kani::any())
                    );
                }
                Vlan::DoubleTagged => {
                    to_test
                        .set_ieee802_1q_s_tag_vlan_identifier(kani::any())
                        .unwrap();
                }
            }

            let _ = DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                vlan,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn cut_ieee802_1q_s_tag() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let mut any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        let mut vlan = match to_test.ethernet_ether_type() {
            constants::CUSTOMER_TAG_802_1Q => Vlan::SingleTagged,
            constants::SERVICE_TAG_802_1Q => Vlan::DoubleTagged,
            _ => return,
        };
        if let Ok(mut to_test) =
            DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(to_test, vlan)
        {
            to_test.cut_ieee802_1q_s_tag();
            if vlan == Vlan::DoubleTagged {
                any_headroom += 4;
                vlan = Vlan::SingleTagged;
            }

            let _ = DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                vlan,
            )
            .unwrap();
        }
    }
}

#[kani::proof]
fn cut_ieee802_1q_s_tag_complete() {
    let mut any_array: [u8; EXTENDED_SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= EXTENDED_SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let mut any_headroom = kani::any_where(|i| *i <= EXTENDED_HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        let vlan = match to_test.ethernet_ether_type() {
            constants::CUSTOMER_TAG_802_1Q => Vlan::SingleTagged,
            constants::SERVICE_TAG_802_1Q => Vlan::DoubleTagged,
            _ => return,
        };
        if let Ok(to_test) =
            DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(to_test, vlan)
        {
            if let Ok(to_test) =
                DataBuffer::<_, Ipv6<Ieee802_1QVlan<Eth>>>::parse_ipv6_layer(to_test)
            {
                if let Ok(mut to_test) =
                    DataBuffer::<_, Tcp<Ipv6<Ieee802_1QVlan<Eth>>>>::parse_tcp_layer(to_test, true)
                {
                    let internal_headroom = to_test.headroom_internal();
                    let data_length = to_test.data_length_internal();
                    let eth_header_start_offset = to_test.header_start_offset(Layer::EthernetII);
                    let eth_header_length = to_test.header_length(Layer::EthernetII);
                    let vlan_header_start_offset =
                        to_test.header_start_offset(Layer::Ieee802_1QVlan);
                    let vlan_header_length = to_test.header_length(Layer::Ieee802_1QVlan);
                    let ipv6_header_start_offset = to_test.header_start_offset(Layer::Ipv6);
                    let ipv6_header_length = to_test.header_length(Layer::Ipv6);
                    let tcp_header_start_offset = to_test.header_start_offset(Layer::Tcp);
                    let tcp_header_length = to_test.header_length(Layer::Tcp);

                    to_test.cut_ieee802_1q_s_tag();
                    if vlan == Vlan::DoubleTagged {
                        any_headroom += 4;
                        // data start
                        assert_eq!(internal_headroom + 4, to_test.headroom_internal());
                        // data length
                        assert_eq!(data_length - 4, to_test.data_length_internal());
                        // vlan header length
                        assert_eq!(
                            vlan_header_length - 4,
                            to_test.header_length(Layer::Ieee802_1QVlan)
                        );
                        // higher layer header offset
                        assert_eq!(
                            ipv6_header_start_offset - 4,
                            to_test.header_start_offset(Layer::Ipv6)
                        );
                        assert_eq!(
                            tcp_header_start_offset - 4,
                            to_test.header_start_offset(Layer::Tcp)
                        );
                    } else {
                        // data start
                        assert_eq!(internal_headroom, to_test.headroom_internal());
                        // data length
                        assert_eq!(data_length, to_test.data_length_internal());
                        // vlan header length
                        assert_eq!(
                            vlan_header_length,
                            to_test.header_length(Layer::Ieee802_1QVlan)
                        );
                        // higher layer header offset
                        assert_eq!(
                            ipv6_header_start_offset,
                            to_test.header_start_offset(Layer::Ipv6)
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
                    assert_eq!(eth_header_length, to_test.header_length(Layer::EthernetII));
                    assert_eq!(
                        vlan_header_start_offset,
                        to_test.header_start_offset(Layer::Ieee802_1QVlan)
                    );
                    assert_eq!(ipv6_header_length, to_test.header_length(Layer::Ipv6));
                    assert_eq!(tcp_header_length, to_test.header_length(Layer::Tcp));
                    assert_eq!(EtherType::CustomerTag as u16, to_test.ethernet_ether_type());

                    let eth = DataBuffer::<_, Eth>::parse_ethernet_layer(
                        to_test.buffer_into_inner(),
                        any_headroom,
                    )
                    .unwrap();
                    let vlan = DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(
                        eth,
                        Vlan::SingleTagged,
                    )
                    .unwrap();
                    let ipv6 =
                        DataBuffer::<_, Ipv6<Ieee802_1QVlan<Eth>>>::parse_ipv6_layer(vlan).unwrap();
                    let _ = DataBuffer::<_, Tcp<Ipv6<Ieee802_1QVlan<Eth>>>>::parse_tcp_layer(
                        ipv6, true,
                    )
                    .unwrap();
                }
            }
        }
    }
}

#[kani::proof]
fn set_ieee802_1q_ether_type() {
    let mut any_array: [u8; SLICE_LENGTH] = kani::any();
    let any_slice_length = kani::any_where(|i| *i <= SLICE_LENGTH);
    let any_slice = &mut any_array[..any_slice_length];

    let any_headroom = kani::any_where(|i| *i <= HEADROOM);

    if let Ok(to_test) = DataBuffer::<_, Eth>::parse_ethernet_layer(any_slice, any_headroom) {
        let vlan = match to_test.ethernet_ether_type() {
            constants::CUSTOMER_TAG_802_1Q => Vlan::SingleTagged,
            constants::SERVICE_TAG_802_1Q => Vlan::DoubleTagged,
            _ => return,
        };
        if let Ok(mut to_test) =
            DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(to_test, vlan)
        {
            to_test.set_ieee802_1q_ether_type(kani::any());

            let _ = DataBuffer::<_, Ieee802_1QVlan<Eth>>::parse_ieee802_1q_layer(
                DataBuffer::<_, Eth>::parse_ethernet_layer(
                    to_test.buffer_into_inner(),
                    any_headroom,
                )
                .unwrap(),
                vlan,
            )
            .unwrap();
        }
    }
}
