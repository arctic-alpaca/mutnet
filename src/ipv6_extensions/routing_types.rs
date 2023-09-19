crate::macros::generate_matching_enum_impl! {
    /// Sources:
    /// <https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-3>
    #[repr(u8)]
    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
    #[cfg_attr(kani, derive(kani::Arbitrary))]
    pub enum RoutingType {
        SourceRoute = 0,
        Nimrod = 1,
        Type2RoutingHeader = 2,
        RplSourceRouteHeader = 3,
        SegmentRoutingHeader = 4,
        Rfc3692StyleExperiment1 = 253,
        Rfc3692StyleExperiment2 = 254,
        Reserved = 255,
    }
}
