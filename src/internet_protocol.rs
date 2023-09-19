crate::macros::generate_matching_enum_impl! {
    /// Sources:
    /// <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>
    #[repr(u8)]
    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
    #[cfg_attr(kani, derive(kani::Arbitrary))]
    pub enum InternetProtocolNumber {
        /// IPv6 Hop-by-Hop Option
        HopByHopOpt = 0,
        /// Internet Control Message
        Icmp = 1,
        /// Internet Group Management
        Igmp = 2,
        /// Gateway-to-Gateway
        Ggp = 3,
        /// IPv4 encapsulation
        Ipv4 = 4,
        /// Stream
        St = 5,
        /// Transmission Control
        Tcp = 6,
        /// Core Based Trees
        Cbt = 7,
        /// Exterior Gateway Protocol
        Egp = 8,
        /// Any private interior gateway (used by Cisco for their IGRP)
        Igp = 9,
        /// BBN RCC Monitoring
        BbnRccMon = 10,
        /// Network Voice Protocol
        NvpIi = 11,
        /// PUP ("PUP: An Internetwork Architecture", XEROX Palo Alto Research Center, CSL-79-10, July 1979)
        Pup = 12,
        /// ARGUS (deprecated according to IANA)
        Argus = 13,
        /// EMCON
        Emcom = 14,
        /// Cross Net Debugger
        Xnet = 15,
        /// CHAOS
        Chaos = 16,
        /// User Datagram
        Udp = 17,
        /// Multiplexing
        Mux = 18,
        /// DCN Measurement Subsystems
        DcnMeas = 19,
        /// Host Monitoring
        Hmp = 20,
        /// Packet Radio Measurement
        Prm = 21,
        /// XEROX NS IDP
        XnsIdp = 22,
        /// Trunk-1
        Trunk1 = 23,
        /// Trunk-2
        Trunk2 = 24,
        /// Leaf-1
        Leaf1 = 25,
        /// Leaf-2
        Leaf2 = 26,
        /// Reliable Data Protocol
        Rdp = 27,
        /// Internet Reliable Transaction
        Irtp = 28,
        /// ISO Transport Protocol Class 4
        IsoTp4 = 29,
        /// Bulk Data Transfer Protocol
        Netblt = 30,
        /// MFE Network Services Protocol
        MfeNsp = 31,
        /// MERIT Internodal Protocol
        MeritInp = 32,
        /// Datagram Congestion Control Protocol
        Dccp = 33,
        /// Third Party Connect Protocol
        Tpc = 34,
        /// Inter-Domain Policy Routing Protocol
        Idpr = 35,
        /// XTP
        Xtp = 36,
        /// Datagram Delivery Protocol
        Ddp = 37,
        /// IDPR Control Message Transport Proto
        IdprCmtp = 38,
        /// TP++ Transport Protocol
        Tppp = 39,
        /// IL Transport Protocol
        Il = 40,
        /// IPv6 encapsulation
        Ipv6 = 41,
        /// Source Demand Routing Protocol
        Sdrp = 42,
        /// Routing Header for IPv6
        Ipv6Routing = 43,
        /// Fragment Header for IPv6
        Ipv6Frag = 44,
        /// Inter-Domain Routing Protocol
        Idrp = 45,
        /// CHAOS
        Rsvp = 46,
        /// Generic Routing Encapsulation
        Gre = 47,
        /// Dynamic Source Routing Protocol
        Dsr = 48,
        /// BNA
        Bna = 49,
        /// Encap Security Payload
        Esp = 50,
        /// Authentication Header
        Auth = 51,
        /// Integrated Net Layer Security TUBA
        INlsp = 52,
        /// IP with Encryption (deprecated according to IANA)
        Swipe = 53,
        /// NBMA Address Resolution Protocol
        Narp = 54,
        /// IP Mobility
        Mbile = 55,
        /// Transport Layer Security Protocol using Kryptonet key management
        Tlsp = 56,
        /// SKIP
        Skip = 57,
        /// ICMP for IPv6
        Ipv6Icmp = 58,
        /// No Next Header for IPv6
        Ipv6NoNxt = 59,
        /// Destination Options for IPv6
        Ipv6DestOpts = 60,
        /// any host internal protocol
        Ahip = 61,
        /// CFTP
        Cftp = 62,
        /// any local network
        Aln = 63,
        /// SATNET and Backroom EXPAK
        SatExpak = 64,
        /// Kryptolan
        Krypotlan = 65,
        /// MIT Remote Virtual Disk Protocol
        Rvd = 66,
        /// Internet Pluribus Packet Core
        Ippc = 67,
        /// any distributed file system
        Adfl = 68,
        /// SATNET Monitoring
        SatMon = 69,
        /// VISA Protocol
        Visa = 70,
        /// Internet Packet Core Utility
        Ipcv = 71,
        /// Computer Protocol Network Executive
        Cpnx = 72,
        /// Computer Protocol Heart Beat
        Cphb = 73,
        /// Wang Span Network
        Wsn = 74,
        /// Packet Video Protocol
        Pvp = 75,
        /// Backroom SATNET Monitoring
        BrSatMon = 76,
        /// SUN ND PROTOCOL-Temporary
        SunNd = 77,
        /// WIDEBAND Monitoring
        WbMon = 78,
        /// WIDEBAND EXPAK
        WbExpak = 79,
        /// ISO Internet Protocol
        IsoIp = 80,
        /// VMTP
        Vmtp = 81,
        /// SECURE-VMTP
        SecureVmtp = 82,
        /// VINES
        Vines = 83,
        /// Internet Protocol Traffic Manager (`<https://www.dslreports.com/forum/r28704884-IPv4-Protocol-84-Question-why-duplicates>`)
        Iptm = 84,
        /// NSFNET-IGP
        NsfnetIgp = 85,
        /// Dissimilar Gateway Protocol
        Dgp = 86,
        /// TCF
        Tcf = 87,
        /// EIGRP
        Eigrp = 88,
        /// OSPFIGP
        Ospfigp = 89,
        /// Sprite RPC Protocol
        SpriteRpc = 90,
        /// Locus Address Resolution Protocol
        Larp = 91,
        /// Multicast Transport Protocol
        Mtp = 92,
        /// AX.25 Frames
        Ax25 = 93,
        /// IP-within-IP Encapsulation Protocol
        Ipip = 94,
        /// Mobile Internetworking Control Pro. (deprecated according to IANA)
        Micp = 95,
        /// Semaphore Communications Sec. Pro.
        SccSp = 96,
        /// Ethernet-within-IP Encapsulation
        Etherip = 97,
        /// Encapsulation Header
        Encap = 98,
        /// any private encryption scheme
        Apes = 99,
        /// GMTP
        Gmtp = 100,
        /// Ipsilon Flow Management Protocol
        Ifmp = 101,
        /// PNNI over IP
        Pnni = 102,
        /// Protocol Independent Multicast
        Pim = 103,
        /// ARIS
        Aris = 104,
        /// SCPS
        Scps = 105,
        /// QNX
        Qnx = 106,
        /// Active Networks
        An = 107,
        /// IP Payload Compression Protocol
        IpComp = 108,
        /// Sitara Networks Protocol
        Snp = 109,
        /// Compaq Peer Protocol
        CompaqPeer = 110,
        /// IPX in IP
        IpxInIp = 111,
        /// Virtual Router Redundancy Protocol
        Vrrp = 112,
        /// PGM Reliable Transport Protocol
        Pgm = 113,
        /// any 0-hop protocol
        Azhp = 114,
        /// Layer Two Tunneling Protocol
        L2tp = 115,
        /// D-II Data Exchange (DDX)
        Ddx = 116,
        /// Interactive Agent Transfer Protocol
        Iatp = 117,
        /// Schedule Transfer Protocol
        Stp = 118,
        /// SpectraLink Radio Protocol
        Srp = 119,
        /// UTI
        Uti = 120,
        /// Simple Message Protocol
        Smp = 121,
        /// Simple Multicast Protocol (deprecated according to IANA)
        Sm = 122,
        /// Performance Transparency Protocol
        Ptp = 123,
        /// ISIS over IPv4
        IsisOverIpv4 = 124,
        /// FIRE
        Fire = 125,
        /// Combat Radio Transport Protocol
        Crtp = 126,
        /// Combat Radio User Datagram
        Crudp = 127,
        /// SSCOPMCE
        Sscopmce = 128,
        /// IPLT
        Iplt = 129,
        /// Secure Packet Shield
        Sps = 130,
        /// Private IP Encapsulation within IP
        Pipe = 131,
        /// Stream Control Transmission Protocol
        Sctp = 132,
        /// Fibre Channel
        Fc = 133,
        /// RSVP-E2E-IGNORE
        RscpE2eIgnore = 134,
        /// Mobility Header
        MobilityHeader = 135,
        /// UDPLite
        UdpLite = 136,
        /// MPLS-in-IP
        MplsInIp = 137,
        /// MANET Protocols
        Manet = 138,
        /// Host Identity Protocol
        HostIdent = 139,
        /// Shim6 Protocol
        Shim6 = 140,
        /// Wrapped Encapsulating Security Payload
        Wesp = 141,
        /// Robust Header Compression
        Rohc = 142,
        /// Ethernet
        Ethernet = 143,
        /// AGGFRAG encapsulation payload for ESP
        Aggfrag = 144,
        /// Use for experimentation and testing
        ExperimentationTesting1 = 253,
        /// Use for experimentation and testing
        ExperimentationTesting2 = 254,
        /// Reserved
        Reserved = 255,

    }
}
