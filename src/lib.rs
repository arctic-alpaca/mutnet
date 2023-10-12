#![doc = include_str!("../README.md")]
#![cfg_attr(
    all(feature = "error_trait", not(feature = "std")),
    feature(error_in_core)
)]
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(unreachable_pub)]
#![allow(private_bounds)]

mod constants;
mod internal_utils;
mod macros;
mod test_utils;
mod utility_traits;

pub mod addresses;
pub mod arp;
pub mod checksum;
pub mod data_buffer;
pub mod error;
pub mod ether_type;
pub mod ethernet;
pub mod ieee802_1q_vlan;
pub mod internet_protocol;
pub mod ipv4;
pub mod ipv6;
pub mod ipv6_extensions;
pub mod multi_step_parser;
pub mod no_previous_header;
pub mod tcp;
pub mod vlan;
