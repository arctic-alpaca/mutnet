pub(crate) trait TcpUdpChecksum {
    fn pseudoheader_checksum(&self) -> u64;
}

pub(crate) trait UpdateIpLength {
    fn update_ip_length(&mut self);
}
