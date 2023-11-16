# 0.5.0 (unreleased)
### Changed
- Set MSRV to 1.74.0 to drop nightly requirement
- **breaking** Change `DataBuffer` layer parsing method names

# 0.4.0 (9. November 2023)
### Added
- `headroom` method to `BufferIntoInner` trait, allows users to know how much of the buffer is headroom
- Documentation and warn on missing documentation

### Changed
- **breaking** Changed `ArpMethodsMut` method names to match other setters
- **breaking** ARP now returns an error on non-supported operation codes
- **breaking** Change `ipv4_options` and `ipv4_options_mut` from Option to empty slices if no options are present
- Improve IPv6 `new()` performance by reducing buffer accesses
- Properly handle atomic IPv6 fragment extensions
- **breaking** Rename `Ipv6ExtTypedHeader` to `Ipv6ExtTypedHeaderError`
- **breaking** `Ipv6ExtMethods::ipv6_extensions` now returns options in the array to indicate the amount of extensions
- **breaking** Refactor project structure
- **breaking** Rename and restructure errors and some other structs
- Improve Docs

### Fixed
- Return an error on a hop by hop IPv6 extension that is not the first extension

### Remove
- Unneeded errors structs

# 0.3.1 (24. October 2023)
### Removed
- paste dependency

# 0.3.0 (24. October 2023)
### Added
- **breaking** UDP support for `parse_network_data()`
- **breaking** IPv4 fragmentation support for `parse_network_data()`
- UDP and IPv4 fragment support in parse_from_iface example

# 0.2.0 (24. October 2023)
### Added
- **breaking** UDP
- CI for tests

### Changed
- Switched proofs from `any_vec` to slices ([b80b788](https://github.com/arctic-alpaca/mutnet/commit/b80b78875e22f9aeb66d706bbe847d6f7218fb7b))

### Fixed
- TCP docs ([62cb561](https://github.com/arctic-alpaca/mutnet/commit/62cb5614b819d304bd38c3239d34c3cfff07f500) & [9601e0b](https://github.com/arctic-alpaca/mutnet/commit/9601e0bd56c1ee3b023453573c4fa830362b1ea3))
- TCP/UDP checksum now uses information from the IPv4/IPv6 header in the pseudo header ([eb14bf4](https://github.com/arctic-alpaca/mutnet/commit/eb14bf42dfdec29e10b9bcd520bbd8075282ed83))

# 0.1.0 (19. September 2023)
### Added
- Initial release
