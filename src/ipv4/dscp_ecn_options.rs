#![allow(clippy::unusual_byte_groupings)]

crate::macros::generate_matching_enum_impl! {
    /// Sources:
    /// <https://en.wikipedia.org/wiki/Differentiated_services>
    /// <https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml>
    #[repr(u8)]
    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
    #[cfg_attr(kani, derive(kani::Arbitrary))]
    pub enum Dscp {
        Cs0 = 0b00_00_0000,
        Cs1 = 0b00_00_1000,
        Cs2 = 0b00_01_0000,
        Cs3 = 0b00_01_1000,
        Cs4 = 0b00_10_0000,
        Cs5 = 0b00_10_1000,
        Cs6 = 0b00_11_0000,
        Cs7 = 0b00_11_1000,
        Af11 = 0b00_00_1010,
        Af12 = 0b00_00_1100,
        Af13 = 0b00_00_1110,
        Af21 = 0b00_01_0010,
        Af22 = 0b00_01_0100,
        Af23 = 0b00_01_0110,
        Af31 = 0b00_01_1010,
        Af32 = 0b00_01_1100,
        Af33 = 0b00_01_1110,
        Af41 = 0b00_10_0010,
        Af42 = 0b00_10_0100,
        Af43 = 0b00_10_0110,
        Ef = 0b00_10_1110,
        VoiceAdmit = 0b00_10_1100,
        Le = 0b00_00_0001,
    }
}

crate::macros::generate_matching_enum_impl! {
    /// Sources:
    /// <https://en.wikipedia.org/wiki/Explicit_Congestion_Notification>
    /// <https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml>
    #[repr(u8)]
    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
    #[cfg_attr(kani, derive(kani::Arbitrary))]
    pub enum Ecn {
        /// Not-ECT (Not ECN-Capable Transport)
        NotEct = 0b0000_00_00,
        /// ECT(1) (ECN-Capable Transport(1))
        Ect1 = 0b0000_00_01,
        /// ECT(0) (ECN-Capable Transport(0))
        Ect0 = 0b0000_00_10,
        /// CE (Congestion Experienced)
        Ce = 0b0000_00_11,
    }
}

crate::macros::generate_matching_enum_impl! {
    /// Sources:
    /// <https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Options>
    /// <https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml#ip-parameters-1>
    #[repr(u8)]
    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
    #[cfg_attr(kani, derive(kani::Arbitrary))]
    pub enum OptionType {
        /// End of Option List
        Eool = 0x00,
        /// No Operation
        Nop = 0x01,
        /// Security (defunct)
        Sec = 0x02,
        /// Record Route
        Rr = 0x07,
        /// Experimental Measurement
        Zsu = 0x0A,
        /// MTU Probe
        Mtup = 0x0B,
        /// MTU Reply
        Mtur = 0x0C,
        /// ENCODE
        Encode = 0x0F,
        /// Quick-Start
        Qs = 0x19,
        /// RFC3692-style Experiment
        Exp = 0x1E,
        /// Time Stamp
        Ts = 0x44,
        /// Traceroute
        Tr = 0x52,
        /// RFC3692-style Experiment
        Exp1 = 0x5E,
        /// Security (RIPSO)
        Sec1 = 0x82,
        /// Loose Source Route
        Lsr = 0x83,
        /// Extended Security (RIPSO)
        ESec = 0x85,
        /// Commercial IP Security Option
        Cipso = 0x86,
        /// Stream ID
        Sid = 0x88,
        /// Strict Source Route
        Ssr = 0x89,
        /// Experimental Access Control
        Visa = 0x8E,
        /// IMI Traffic Descriptor
        Imitd = 0x90,
        /// Extended Internet Protocol
        Eip = 0x91,
        /// Address Extension
        Addrext = 0x93,
        /// Router Alert
        Rtralt = 0x94,
        /// Selective Directed Broadcast
        Sdb = 0x95,
        /// Dynamic Packet State
        Dps = 0x97,
        /// Upstream Multicast Packet
        Ump = 0x98,
        /// RFC3692-style Experiment
        Exp2 = 0x9E,
        /// Experimental Flow Control
        Finn = 0xCD,
        /// RFC3692-style Experiment
        Exp3 = 0xDE,
    }
}
