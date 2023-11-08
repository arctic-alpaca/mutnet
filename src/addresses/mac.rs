//! MAC address type alias and utility methods.

/// MAC Address in six octets.
pub type MacAddress = [u8; 6];

/// Returns `true` if a [`MacAddress`] is the broadcast address.
///
/// # Examples
///
/// ```
/// # use mutnet::addresses::mac::{MacAddress, is_broadcast};
/// let non_broadcast_addr: MacAddress = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
/// let broadcast_addr: MacAddress = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
/// assert_eq!(is_broadcast(&non_broadcast_addr), false);
/// assert_eq!(is_broadcast(&broadcast_addr), true);
/// ```
pub fn is_broadcast(mac_addr: &MacAddress) -> bool {
    mac_addr == &[0xFF; 6]
}

/// Returns `true` if the provided [`MacAddress`] is a multicast address.
///
/// # Examples
///
/// ```
/// # use mutnet::addresses::mac::{MacAddress, is_multicast};
/// let non_multicast_addr: MacAddress = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
/// let multicast_addr: MacAddress = [0xAD, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
/// assert_eq!(is_multicast(&non_multicast_addr), false);
/// assert_eq!(is_multicast(&multicast_addr), true);
/// ```
pub fn is_multicast(mac_addr: &MacAddress) -> bool {
    mac_addr[0] & 0b0000_0001 == 1
}
