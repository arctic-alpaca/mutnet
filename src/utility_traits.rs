pub(crate) trait TcpUdpChecksum {
    fn pseudoheader_checksum(&self, tcp_udp_length: usize) -> u64;
}

pub(crate) trait UpdateIpLength {
    fn update_ip_length(&mut self);
}
