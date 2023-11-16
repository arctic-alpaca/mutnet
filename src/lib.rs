//! mutnet is an unsafe-free and allocation-free, zero-dependency, no-std network protocol parsing and in-place manipulation library.
//!
//! # Table of contents
//! - [Usage](#usage)
//!     - [Headroom](#headroom)
//!     - [Parsing](#parsing)
//!     - [Manipulation](#manipulation)
//! - [Feature flags](#feature-flags)
//!
//! # Usage
//! Network data is wrapped in a [`DataBuffer`](data_buffer::DataBuffer) and combined with a
//! stack of protocol metadata to keep track of individual protocol header's start and length.
//!
//! ## Headroom
//! Headroom is "empty" space at the start of the wrapped network data buffer used to accommodate
//! length changes of the parsed protocol headers.
//! Using headroom for length changes allows only copying header data which, in general, is less work
//! than copying the payload.
//! For example if an IPv4 header's length should be increased for additional options, all header
//! information before the options is moved by the required amount into the headroom leaving space
//! for more options.
//!
//! ```text
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Headroom   |     Header Data       |         Payload         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
//! -> some method manipulates the headers in a way that requires more space ->
//! Headroom shrinks -> header data is partially copied -> new data is inserted ->
//!
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Headroom|   Header   | *** |  Data   |         Payload         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! *** = Data inserted into the headers.
//!
//! ```
//! The headroom has to be already present in the network data buffer to be wrapped by [`DataBuffer`](data_buffer::DataBuffer).
//! If no header mutation is required, the headroom can be ignored.
//!
//! ## Parsing
//!
//! After parsing data by creating the appropriate [`DataBuffer`](data_buffer::DataBuffer) with
//! metadata stack, the `ProtocolMethods` traits (e.g. [`TcpMethods`](tcp::TcpMethods)) are used to access the header data.
//!
//! #### Avoid copying data
//! If the network data buffer implements [`Copy`], the [`DataBuffer`](data_buffer::DataBuffer)
//! will take a copy of it and will copy the buffer at every parsing step (e.g. Ethernet -> Ipv4).
//! For this reason, it is advised to use references or non-[`Copy`] containers ([`Vec`], etc).
//!
//! ### Example
//! ```rust
//! use mutnet::data_buffer::DataBuffer;
//! use mutnet::ethernet::Eth;
//! use mutnet::ipv4::Ipv4;
//! use mutnet::tcp::{Tcp, TcpMethods};
//! # #[rustfmt::skip]
//! #  const ETH_IPV4_TCP: [u8; 64] = [
//! #     // Dst
//! #     0x00, 0x80, 0x41, 0xAE, 0xFD, 0x7E,
//! #     // Src
//! #     0x7E, 0xFD, 0xAE, 0x41, 0x80, 0x00,
//! #     // Ether type (IPv4)
//! #     0x08, 0x00,
//! #     // Payload
//! #     // IPv4
//! #     // Version & IHL
//! #     0x46,
//! #     // DSCP & ECN
//! #     0b0010_1000,
//! #     // Total length
//! #     0x00, 0x32,
//! #     // Identification
//! #     0x12, 0x34,
//! #     // Flags & Fragment offset
//! #     0b101_00000, 0x03,
//! #     // TTL
//! #     0x01,
//! #     // Protocol (TCP)
//! #     0x06,
//! #     // Header Checksum
//! #     0x06, 0x61,
//! #     // Source
//! #     0x7f, 0x00, 0x00, 0x1,
//! #     // Destination
//! #     0x7f, 0x00, 0x00, 0x1,
//! #     // Options
//! #     0x02, 0x04, 0xFF, 0xFF,
//! #     // Payload
//! #     // TCP
//! #     // Source port
//! #     0x12, 0x34,
//! #     // Destination port
//! #     0x45, 0x67,
//! #     // Sequence number
//! #     0x12, 0x34, 0x56, 0x78,
//! #     // Acknowledgment number
//! #     0x09, 0x87, 0x65, 0x43,
//! #     // Data offset, reserved bits, flags
//! #     0x50, 0b0101_0101,
//! #     // Window
//! #     0x12, 0x45,
//! #     // Checksum
//! #     0x19, 0xB8,
//! #     // Urgent pointer
//! #     0x56, 0x78,
//! #     // payload
//! #     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
//! # ];
//!
//! let network_data_ref = &ETH_IPV4_TCP;
//! let headroom = 0;
//!
//! // Parse network data without headroom.
//! let ethernet = DataBuffer::<&[u8;64], Eth>::parse_ethernet_layer(network_data_ref, headroom).unwrap();
//! // The network data buffer type can usually be elided.
//! let check_ipv4_checksum = true;
//! let ipv4 = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(ethernet, check_ipv4_checksum).unwrap();
//! let check_tcp_checksum = true;
//! let tcp = DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(ipv4, check_tcp_checksum).unwrap();
//!
//! // The mutnet::tcp::TcpMethods trait needs to be in scope to access non-mutable TCP methods.
//! assert_eq!(tcp.tcp_source_port(), 0x1234);
//! ```
//!
//! ## Manipulation
//!
//! For header manipulation, the [`DataBuffer`](data_buffer::DataBuffer) needs to be created
//! with a mutable network data buffer.
//! If this is the case the `ProtocolMethodsMut` traits (e.g. [`TcpMethodsMut`](tcp::TcpMethodsMut)) allow mutating the data
//! ```rust
//! use mutnet::data_buffer::DataBuffer;
//! use mutnet::ethernet::Eth;
//! use mutnet::ipv4::Ipv4;
//! use mutnet::tcp::{Tcp, TcpMethods, TcpMethodsMut};
//! # #[rustfmt::skip]
//! #  const ETH_IPV4_TCP: [u8; 64] = [
//! #     // Dst
//! #     0x00, 0x80, 0x41, 0xAE, 0xFD, 0x7E,
//! #     // Src
//! #     0x7E, 0xFD, 0xAE, 0x41, 0x80, 0x00,
//! #     // Ether type (IPv4)
//! #     0x08, 0x00,
//! #     // Payload
//! #     // IPv4
//! #     // Version & IHL
//! #     0x46,
//! #     // DSCP & ECN
//! #     0b0010_1000,
//! #     // Total length
//! #     0x00, 0x32,
//! #     // Identification
//! #     0x12, 0x34,
//! #     // Flags & Fragment offset
//! #     0b101_00000, 0x03,
//! #     // TTL
//! #     0x01,
//! #     // Protocol (TCP)
//! #     0x06,
//! #     // Header Checksum
//! #     0x06, 0x61,
//! #     // Source
//! #     0x7f, 0x00, 0x00, 0x1,
//! #     // Destination
//! #     0x7f, 0x00, 0x00, 0x1,
//! #     // Options
//! #     0x02, 0x04, 0xFF, 0xFF,
//! #     // Payload
//! #     // TCP
//! #     // Source port
//! #     0x12, 0x34,
//! #     // Destination port
//! #     0x45, 0x67,
//! #     // Sequence number
//! #     0x12, 0x34, 0x56, 0x78,
//! #     // Acknowledgment number
//! #     0x09, 0x87, 0x65, 0x43,
//! #     // Data offset, reserved bits, flags
//! #     0x50, 0b0101_0101,
//! #     // Window
//! #     0x12, 0x45,
//! #     // Checksum
//! #     0x19, 0xB8,
//! #     // Urgent pointer
//! #     0x56, 0x78,
//! #     // payload
//! #     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
//! # ];
//!
//! // For demonstration purposes, the data is copied into an array.
//! let mut network_data = [0;100];
//! network_data[36..].copy_from_slice(&ETH_IPV4_TCP);
//! let network_data_ref_mut = &mut network_data;
//! // Set the headroom accordingly.
//! let headroom = 36;
//!
//! // Parse network data without headroom.
//! let ethernet = DataBuffer::<&mut [u8;100], Eth>::parse_ethernet_layer(network_data_ref_mut, headroom).unwrap();
//! // The network data buffer type can usually be elided.
//! let check_ipv4_checksum = true;
//! let ipv4 = DataBuffer::<_, Ipv4<Eth>>::parse_ipv4_layer(ethernet, check_ipv4_checksum).unwrap();
//! let check_tcp_checksum = true;
//! let mut tcp = DataBuffer::<_, Tcp<Ipv4<Eth>>>::parse_tcp_layer(ipv4, check_tcp_checksum).unwrap();
//!
//! // The mutnet::tcp::TcpMethods trait needs to be in scope to access non-mutating TCP methods.
//! assert_eq!(tcp.tcp_source_port(), 0x1234);
//!
//! // The mutnet::tcp::TcpMethodsMut trait needs to be in scope to access mutating TCP methods.
//! tcp.set_tcp_source_port(0xAAAA);
//! assert_eq!(tcp.tcp_source_port(), 0xAAAA);
//! ```
//!
//!
//! # Feature flags
//!
//! Name | Description | Default?
//! ---|---|---
//! `error_trait` | use unstable `core::error:Error`, only available in nightly | No
//! `std` | use `std` | Yes
//!  ... | All other features are for development usage only | No
//!
#![cfg_attr(
    all(feature = "error_trait", not(feature = "std")),
    feature(error_in_core)
)]
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![forbid(unreachable_pub)]
#![warn(missing_docs)]

mod internal_utils;
mod test_utils;
mod utility_traits;

pub mod addresses;
pub mod arp;
pub mod checksum;
pub mod data_buffer;
pub mod error;
pub mod ethernet;
pub mod ieee802_1q_vlan;
pub mod ipv4;
pub mod ipv6;
pub mod ipv6_extensions;
pub mod multi_step_parser;
pub mod no_previous_header;
pub mod tcp;
pub mod typed_protocol_headers;
pub mod udp;
