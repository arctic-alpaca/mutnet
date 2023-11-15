pub(crate) trait PseudoHeaderChecksum {
    fn pseudo_header_checksum(&self) -> u64;
}

pub(crate) trait UpdateIpLength {
    fn update_ip_length(&mut self);
}
