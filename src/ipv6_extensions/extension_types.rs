crate::macros::generate_matching_enum_impl! {
    /// Sources:
    /// <https://en.wikipedia.org/wiki/IPv6_packet#Extension_headers>
    #[repr(u8)]
    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
    #[cfg_attr(kani, derive(kani::Arbitrary))]
    pub enum Ipv6Extension {
        HopByHop = 0,
        Routing = 43,
        Fragment = 44,
        DestinationOptions = 60,
    }
}
