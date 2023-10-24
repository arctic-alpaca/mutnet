# mutnet

mutnet is an unsafe-free and allocation-free, zero-dependency, no-std network protocol parsing and in-place manipulation library.


[![Crates.io](https://img.shields.io/crates/v/mutnet)](https://crates.io/crates/mutnet)
[![Documentation](https://docs.rs/mutnet/badge.svg)](https://docs.rs/mutnet)


## Nightly
This crate makes use of [type privacy](https://github.com/rust-lang/rust/issues/48054) and thus only compiles
on nightly Rust. It currently looks like this [limitation should be lifted](https://github.com/rust-lang/rust/pull/113126) with Rust 1.74.0.

## Supported Protocols
- Ethernet II
- IEEE 802.1Q VLAN tags
- ARP (request & reply for Ethernet and IPv4)
- IPv4
- IPv6 (no Jumbograms)
  - IPv6 Extensions (fragment, hop by hop, destination options, routing)
- TCP
- UDP


## Safety & Panics
mutnet makes use of `#[forbid(unsafe_code)]` to ensure the absence of unsafe code.

The absence of panics for all parsing, lookup and manipulation methods is checked via the 
[Kani](https://github.com/model-checking/kani) verifier.

## Usage
You can either use the provided `parse_network_data(...)` method or create your own parser by chaining
protocol parsing steps as required.

Data access and manipulation methods for every layer are implemented in traits.
Please see [docs.rs](https://docs.rs/mutnet/latest/mutnet/all.html) for a list of all available method traits.

### IPv6 Extension
To prevent "endless" parsing of IPv6 extension headers, any method parsing IPv6 extensions requires a const generic
parameter limiting the amount of extension that will be parsed.

### Avoiding Copying When Parsing
When a new layer is parsed (`new(...)` & `new_from_lower(...`), the underlying data buffer is moved to a new
type/struct.
This move leads to a full copy of the data if an array is used as the parameter to the initial `new(...)` call.
To prevent this, use a (mutable) reference to a smart pointer (like a Vector).

### Length Changes
To change the length of a protocol (e.g. add options to IPv4), the header needs to grow or shrink.
Typically, moving the header data before the payload leads to less data that needs to be moved (copied).
To move the header data, some empty space before the start of the network data is required.
This space is called headroom.
mutnet expects the user to supply properly structured data if length modifying methods will be used.

```text
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Headroom   |                Network Data                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Examples
```rust ignore
fn print_eth_source(data: &[u8]) {
  let eth = DataBuffer::<_, Eth>::new(data, 0).unwrap();
  println!("Eth source: {:?}", eth.ethernet_source());
}
```

For more see [parse_from_iface.rs](examples/parse_from_iface.rs).

## Roadmap
- [ ] Additional protocols, see [Protocols](#protocols)
- [ ] Improved benchmarks
- [ ] TLV iterator
- [ ] IPv4 options iterator
- [ ] Insertion of IPv6 extensions into existing IPv6 extensions layer
- [ ] Vlan & IPv6 extensions layer insertion and removal

#### Protocols Roadmap
- [ ] ICMP
- [ ] ICMPv6

## Limitations
Any layer may only occur once per parsed data buffer.

## Design 
[Design](Design.md) lists some details about the design of this crate.

## Features
- `error_trait`: use unstable `core::error:Error`, only available in nightly
- `std`: use std for `std::error::Error` (enabled by default)
- All other features are for development usage only

## License
mutnet is licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) 
or [MIT license](LICENSE-MIT) at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in 
this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, 
without any additional terms or conditions. 