//! Ethernet II implementation and Ethernet II specific errors.

pub use method_traits::*;

use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderMetadata, HeaderMetadataMut, Layer,
};
use crate::data_buffer::{DataBuffer, EthernetMarker, Payload, PayloadMut};
use crate::error::{LengthExceedsAvailableSpaceError, UnexpectedBufferEndError};
use crate::ieee802_1q_vlan::UpdateEtherTypeBelowIeee802_1q;
use crate::internal_utils::check_and_calculate_data_length;
use crate::typed_protocol_headers::EtherType;

mod method_traits;

#[cfg(all(feature = "remove_checksum", feature = "verify_ethernet", kani))]
mod verification;

/// Ethernet II metadata.
///
/// Contains metadata about the Ethernet II header in the parsed data buffer.
#[derive(Eq, PartialEq, Hash, Copy, Clone, Debug)]
pub struct Eth {
    /// Amount of headroom.
    headroom: usize,
    /// Header length.
    header_length: usize,
    /// Length of the network data.
    data_length: usize,
}

// Marker traits implemented for Ethernet II
impl EthernetMarker for Eth {}

impl<B> DataBuffer<B, Eth>
where
    B: AsRef<[u8]>,
{
    /// Parses data and creates a new [`DataBuffer`] for an Ethernet layer.
    ///
    /// The provided `headroom` indicates the amount of headroom in the provided `buf`.
    ///
    /// # Errors
    ///
    /// Returns an error if the provided data buffer is shorter than expected.
    #[inline]
    pub fn parse_ethernet_layer(
        buf: B,
        headroom: usize,
    ) -> Result<DataBuffer<B, Eth>, UnexpectedBufferEndError> {
        let data_length =
            check_and_calculate_data_length(buf.as_ref().len(), headroom, HEADER_MIN_LEN)?;

        Ok(DataBuffer {
            header_metadata: Eth {
                headroom,
                header_length: HEADER_MIN_LEN,
                data_length,
            },
            buffer: buf,
        })
    }
}

impl HeaderMetadata for Eth {
    #[inline]
    fn headroom_internal(&self) -> usize {
        self.headroom
    }

    #[inline]
    fn header_start_offset(&self, _layer: Layer) -> usize {
        0
    }

    /// By returning 0 if the layer does not exist, it is possible to use header length in calculations
    /// that would otherwise require branches to check whether a layer exists.
    #[inline]
    fn header_length(&self, layer: Layer) -> usize {
        if layer == LAYER {
            self.header_length
        } else {
            0
        }
    }

    #[inline]
    fn layer(&self) -> Layer {
        LAYER
    }

    #[inline]
    fn data_length_internal(&self) -> usize {
        self.data_length
    }
}

impl HeaderMetadataMut for Eth {
    #[inline]
    fn headroom_internal_mut(&mut self) -> &mut usize {
        &mut self.headroom
    }

    #[inline]
    fn increase_header_start_offset(&mut self, _increase_by: usize, _layer: Layer) {
        unreachable!("The lowest layer cannot have its header start offset changed")
    }

    #[inline]
    fn decrease_header_start_offset(&mut self, _decrease_by: usize, _layer: Layer) {
        unreachable!("The lowest layer cannot have its header start offset changed")
    }

    #[inline]
    fn header_length_mut(&mut self, _layer: Layer) -> &mut usize {
        &mut self.header_length
    }

    #[inline]
    fn set_data_length(
        &mut self,
        data_length: usize,
        buffer_length: usize,
    ) -> Result<(), LengthExceedsAvailableSpaceError> {
        if data_length + self.headroom > buffer_length {
            Err(LengthExceedsAvailableSpaceError {
                required_space: data_length,
                available_space: buffer_length - self.headroom,
            })
        } else {
            self.data_length = data_length;
            Ok(())
        }
    }
}

impl<B, HM> EthernetMethods for DataBuffer<B, HM>
where
    B: AsRef<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + EthernetMarker,
{
}

impl<B, HM> EthernetMethodsMut for DataBuffer<B, HM>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + EthernetMarker + Sized,
{
}

impl<B, HM> UpdateEtherTypeBelowIeee802_1q for DataBuffer<B, HM>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + EthernetMarker + Sized,
{
    #[inline]
    fn set_single_tagged(&mut self) {
        self.set_ethernet_ether_type(EtherType::CustomerTag);
    }

    #[inline]
    fn set_double_tagged(&mut self) {
        self.set_ethernet_ether_type(EtherType::ServiceTag);
    }
}

impl<B> Payload for DataBuffer<B, Eth>
where
    B: AsRef<[u8]>,
{
    #[inline]
    fn payload(&self) -> &[u8] {
        &self.data_buffer_starting_at_header(LAYER)[self.header_length(LAYER)..]
    }

    #[inline]
    fn payload_length(&self) -> usize {
        self.payload().len()
    }
}

impl<B> PayloadMut for DataBuffer<B, Eth>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    fn payload_mut(&mut self) -> &mut [u8] {
        let payload_start = self.header_length(LAYER);
        &mut self.data_buffer_starting_at_header_mut(LAYER)[payload_start..]
    }
}

#[cfg(test)]
mod tests {
    use crate::data_buffer::traits::HeaderMetadataMut;
    use crate::data_buffer::{DataBuffer, Payload, PayloadMut};
    use crate::error::{LengthExceedsAvailableSpaceError, UnexpectedBufferEndError};
    use crate::ethernet::{Eth, EthernetMethods, EthernetMethodsMut};
    use crate::test_utils::copy_into_slice;
    use crate::typed_protocol_headers::EtherType;

    const ETHERNET_FRAME: [u8; 64] = [
        0x00, 0x80, 0x41, 0xAE, 0xFD, 0x7E, // Dst
        0x7E, 0xFD, 0xAE, 0x41, 0x80, 0x00, // Src
        0x08, 0x00, // Ether type
        // Payload
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    #[test]
    fn new() {
        assert!(DataBuffer::<_, Eth>::parse_ethernet_layer(ETHERNET_FRAME, 0).is_ok());
    }

    #[test]
    fn new_data_buffer_too_short() {
        assert_eq!(
            Err(UnexpectedBufferEndError {
                expected_length: 14,
                actual_length: 12,
            }),
            DataBuffer::<_, Eth>::parse_ethernet_layer(&ETHERNET_FRAME[..12], 0)
        );
    }

    #[test]
    fn new_headroom_out_of_range() {
        assert_eq!(
            Err(UnexpectedBufferEndError {
                expected_length: 14,
                actual_length: 0,
            }),
            DataBuffer::<_, Eth>::parse_ethernet_layer(&ETHERNET_FRAME, ETHERNET_FRAME.len() + 1)
        );
    }

    #[test]
    fn ethernet_destination() {
        let ethernet_frame = DataBuffer::<_, Eth>::parse_ethernet_layer(ETHERNET_FRAME, 0).unwrap();
        assert_eq!(
            [0x00, 0x80, 0x41, 0xAE, 0xFD, 0x7E],
            ethernet_frame.ethernet_destination()
        );
    }

    #[test]
    fn ethernet_source() {
        let ethernet_frame = DataBuffer::<_, Eth>::parse_ethernet_layer(ETHERNET_FRAME, 0).unwrap();
        assert_eq!(
            [0x7E, 0xFD, 0xAE, 0x41, 0x80, 0x00],
            ethernet_frame.ethernet_source()
        );
    }

    #[test]
    fn ethernet_ether_type() {
        let ethernet_frame = DataBuffer::<_, Eth>::parse_ethernet_layer(ETHERNET_FRAME, 0).unwrap();
        assert_eq!(0x0800, ethernet_frame.ethernet_ether_type());
    }

    #[test]
    fn ethernet_typed_ether_type() {
        let ethernet_frame = DataBuffer::<_, Eth>::parse_ethernet_layer(ETHERNET_FRAME, 0).unwrap();
        assert_eq!(
            Ok(EtherType::Ipv4),
            ethernet_frame.ethernet_typed_ether_type()
        );
    }

    #[test]
    fn set_ethernet_destination() {
        let mut ethernet_frame =
            DataBuffer::<_, Eth>::parse_ethernet_layer(ETHERNET_FRAME, 0).unwrap();
        assert_eq!(
            [0x00, 0x80, 0x41, 0xAE, 0xFD, 0x7E],
            ethernet_frame.ethernet_destination()
        );
        ethernet_frame.set_ethernet_destination(&[0x7E, 0xFD, 0xAE, 0x41, 0x80, 0x00]);
        assert_eq!(
            [0x7E, 0xFD, 0xAE, 0x41, 0x80, 0x00],
            ethernet_frame.ethernet_destination()
        );
    }

    #[test]
    fn set_ethernet_source() {
        let mut ethernet_frame =
            DataBuffer::<_, Eth>::parse_ethernet_layer(ETHERNET_FRAME, 0).unwrap();
        assert_eq!(
            [0x7E, 0xFD, 0xAE, 0x41, 0x80, 0x00],
            ethernet_frame.ethernet_source()
        );
        ethernet_frame.set_ethernet_source(&[0x00, 0x80, 0x41, 0xAE, 0xFD, 0x7E]);
        assert_eq!(
            [0x00, 0x80, 0x41, 0xAE, 0xFD, 0x7E],
            ethernet_frame.ethernet_source()
        );
    }

    #[test]
    fn set_ethernet_ether_type() {
        let mut ethernet_frame =
            DataBuffer::<_, Eth>::parse_ethernet_layer(ETHERNET_FRAME, 0).unwrap();
        assert_eq!(0x0800, ethernet_frame.ethernet_ether_type());
        ethernet_frame.set_ethernet_ether_type(EtherType::Ipv6);
        assert_eq!(EtherType::Ipv6 as u16, ethernet_frame.ethernet_ether_type());
    }

    #[test]
    fn payload() {
        let ethernet_frame = DataBuffer::<_, Eth>::parse_ethernet_layer(ETHERNET_FRAME, 0).unwrap();
        assert_eq!(
            &[
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            ],
            ethernet_frame.payload()
        );
    }

    #[test]
    fn payload_length() {
        let ethernet_frame = DataBuffer::<_, Eth>::parse_ethernet_layer(ETHERNET_FRAME, 0).unwrap();
        assert_eq!(50, ethernet_frame.payload_length());
    }

    #[test]
    fn payload_mut() {
        let mut ethernet_frame =
            DataBuffer::<_, Eth>::parse_ethernet_layer(ETHERNET_FRAME, 0).unwrap();

        assert_eq!(
            &[
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            ],
            ethernet_frame.payload_mut()
        );
    }

    #[test]
    fn set_data_length() {
        let mut ethernet_frame =
            DataBuffer::<_, Eth>::parse_ethernet_layer(ETHERNET_FRAME, 0).unwrap();
        ethernet_frame
            .set_data_length(30, ETHERNET_FRAME.len())
            .unwrap();
        assert_eq!(16, ethernet_frame.payload_length());

        assert_eq!(
            Err(LengthExceedsAvailableSpaceError {
                required_space: 65,
                available_space: 64,
            }),
            ethernet_frame.set_data_length(65, ETHERNET_FRAME.len())
        );
        let mut data = [0x00; 100];
        copy_into_slice(&mut data, &ETHERNET_FRAME, 10);
        let data_len = data.len();
        let mut ethernet_frame = DataBuffer::<_, Eth>::parse_ethernet_layer(&mut data, 10).unwrap();
        assert_eq!(
            Err(LengthExceedsAvailableSpaceError {
                required_space: 99,
                available_space: 90,
            }),
            ethernet_frame.set_data_length(99, data_len)
        );
    }
}
