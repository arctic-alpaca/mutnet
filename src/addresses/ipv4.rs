//! IPv4 address type alias and utility methods.

/// IPv4 Address in four octets.
pub type Ipv4Address = [u8; 4];

/// Checks whether an [`Ipv4Address`] is a multicast address.
///
/// # Examples
///
/// ```
/// # use mutnet::addresses::ipv4::{Ipv4Address, is_multicast};
/// let non_multicast_addr: Ipv4Address = [127, 0, 0, 1];
/// let multicast_addr: Ipv4Address = [224, 0, 0, 0];
/// assert_eq!(is_multicast(&non_multicast_addr), false);
/// assert_eq!(is_multicast(&multicast_addr), true);
/// ```
pub fn is_multicast(ip_addr: &Ipv4Address) -> bool {
    ip_addr[0] & 0b1111_0000 == 0b1110_0000
}

/// Checks whether an [`Ipv4Address`] is the limited broadcast address.
///
/// # Examples
///
/// ```
/// # use mutnet::addresses::ipv4::{Ipv4Address, is_limited_broadcast};
/// let non_limited_broadcast_addr: Ipv4Address = [127, 0, 0, 1];
/// let limited_broadcast_addr: Ipv4Address = [255, 255, 255, 255];
/// assert_eq!(is_limited_broadcast(&non_limited_broadcast_addr), false);
/// assert_eq!(is_limited_broadcast(&limited_broadcast_addr), true);
/// ```
pub fn is_limited_broadcast(ip_addr: &Ipv4Address) -> bool {
    ip_addr[..] == [255; 4]
}

/// Checks whether an [`Ipv4Address`] is the a loopback address.
///
/// # Examples
///
/// ```
/// # use mutnet::addresses::ipv4::{Ipv4Address, is_loopback};
/// let non_loopback_addr: Ipv4Address = [192, 168, 0, 1];
/// let loopback_addr: Ipv4Address = [127, 0, 0, 1];
/// assert_eq!(is_loopback(&non_loopback_addr), false);
/// assert_eq!(is_loopback(&loopback_addr), true);
/// ```
pub fn is_loopback(ip_addr: &Ipv4Address) -> bool {
    ip_addr[0] == 127
}
