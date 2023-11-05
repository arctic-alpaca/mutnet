//! IEEE 802.1Q type and method traits.

mod error;
mod method_traits;

pub use error::*;
pub use method_traits::*;

#[cfg(all(feature = "remove_checksum", feature = "verify_vlan", kani))]
mod verification;

use crate::data_buffer::traits::HeaderInformationExtraction;
use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderInformation, HeaderInformationMut, Layer,
};
use crate::data_buffer::{
    BufferIntoInner, DataBuffer, EthernetMarker, Ieee802_1QVlanMarker, Payload, PayloadMut,
};
use crate::error::UnexpectedBufferEndError;
use crate::internal_utils::{check_and_calculate_data_length, header_start_offset_from_phi};
use crate::no_previous_header::NoPreviousHeaderInformation;
use crate::vlan::Vlan;

/// IEEE 802.1Q metadata.
///
/// Contains meta data about the IEEE 802.1Q header in the parsed data buffer.
#[derive(Eq, PartialEq, Hash, Copy, Clone, Debug)]
pub struct Ieee802_1QVlan<PHI: HeaderInformation + HeaderInformationMut> {
    header_start_offset: usize,
    header_length: usize,
    previous_header_information: PHI,
}

impl<B, PHI> DataBuffer<B, Ieee802_1QVlan<PHI>>
where
    B: AsRef<[u8]>,
    PHI: HeaderInformation + HeaderInformationMut + Copy,
{
    /// Parses `buf` and creates a new [DataBuffer] for an IEEE 802.1Q layer with no previous layers.
    ///
    /// `headroom` indicates the amount of headroom in the provided `buf`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided data buffer is shorter than expected.
    /// - no customer tag is found if `expected_vlan_tag` indicates double tagging.
    #[inline]
    pub fn new(
        buf: B,
        headroom: usize,
        expected_vlan_tags: Vlan,
    ) -> Result<DataBuffer<B, Ieee802_1QVlan<NoPreviousHeaderInformation>>, ParseIeee802_1QError>
    {
        let lower_layer_data_buffer =
            DataBuffer::<B, NoPreviousHeaderInformation>::new(buf, headroom)?;
        DataBuffer::<B, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new_from_lower(
            lower_layer_data_buffer,
            expected_vlan_tags,
        )
    }

    /// Consumes the `lower_layer_data_buffer` and creates a new [DataBuffer] with an additional
    /// IEEE 802.1Q layer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided data buffer is shorter than expected.
    /// - no customer tag is found if `expected_vlan_tag` indicates double tagging.
    #[inline]
    pub fn new_from_lower(
        lower_layer_data_buffer: impl HeaderInformation
            + Payload
            + BufferIntoInner<B>
            + HeaderInformationExtraction<PHI>,
        expected_vlan_tag: Vlan,
    ) -> Result<DataBuffer<B, Ieee802_1QVlan<PHI>>, ParseIeee802_1QError> {
        let previous_header_information = lower_layer_data_buffer.extract_header_information();

        let vlan_header_length = match expected_vlan_tag {
            Vlan::SingleTagged => {
                check_and_calculate_data_length::<ParseIeee802_1QError>(
                    lower_layer_data_buffer.payload_length(),
                    0,
                    HEADER_MIN_LEN_SINGLE_TAGGED,
                )?;
                HEADER_MIN_LEN_SINGLE_TAGGED
            }
            Vlan::DoubleTagged => {
                check_and_calculate_data_length::<ParseIeee802_1QError>(
                    lower_layer_data_buffer.payload_length(),
                    0,
                    HEADER_MIN_LEN_DOUBLE_TAGGED,
                )?;

                if lower_layer_data_buffer.payload()[DOUBLE_TAGGED_C_TAG_INDICATOR] != [0x81, 0x00]
                {
                    return Err(ParseIeee802_1QError::STagWithoutCTag(STagWithoutCTagError));
                }

                HEADER_MIN_LEN_DOUBLE_TAGGED
            }
        };

        Ok(Self {
            header_information: Ieee802_1QVlan {
                header_start_offset: header_start_offset_from_phi(previous_header_information),
                header_length: vlan_header_length,
                previous_header_information: *previous_header_information,
            },
            buffer: lower_layer_data_buffer.buffer_into_inner(),
        })
    }
}
impl<PHI> EthernetMarker for Ieee802_1QVlan<PHI> where
    PHI: HeaderInformation + HeaderInformationMut + EthernetMarker
{
}
impl<PHI> Ieee802_1QVlanMarker for Ieee802_1QVlan<PHI> where
    PHI: HeaderInformation + HeaderInformationMut
{
}

impl<B, H> Ieee802_1QMethods for DataBuffer<B, H>
where
    B: AsRef<[u8]>,
    H: HeaderInformation + HeaderInformationMut + Ieee802_1QVlanMarker,
{
}
impl<B, H> Ieee802_1QMethodsMut for DataBuffer<B, H>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    H: HeaderInformation + HeaderInformationMut + Ieee802_1QVlanMarker,
    DataBuffer<B, H>: UpdateEtherTypeBelowIeee802_1q,
{
}

impl<B> UpdateEtherTypeBelowIeee802_1q
    for DataBuffer<B, Ieee802_1QVlan<NoPreviousHeaderInformation>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    fn set_single_tagged(&mut self) {}

    #[inline]
    fn set_double_tagged(&mut self) {}
}

impl<PHI> HeaderInformation for Ieee802_1QVlan<PHI>
where
    PHI: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn headroom_internal(&self) -> usize {
        self.previous_header_information.headroom_internal()
    }

    #[inline]
    fn header_start_offset(&self, layer: Layer) -> usize {
        if layer == LAYER {
            self.header_start_offset
        } else {
            self.previous_header_information.header_start_offset(layer)
        }
    }

    #[inline]
    fn header_length(&self, layer: Layer) -> usize {
        if layer == LAYER {
            self.header_length
        } else {
            self.previous_header_information.header_start_offset(layer)
        }
    }

    #[inline]
    fn layer(&self) -> Layer {
        LAYER
    }

    #[inline]
    fn data_length(&self) -> usize {
        self.previous_header_information.data_length()
    }
}

impl<PHI> HeaderInformationMut for Ieee802_1QVlan<PHI>
where
    PHI: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn headroom_internal_mut(&mut self) -> &mut usize {
        self.previous_header_information.headroom_internal_mut()
    }

    #[inline]
    fn increase_header_start_offset(&mut self, increase_by: usize, layer: Layer) {
        if layer != LAYER {
            self.header_start_offset += increase_by;
            self.previous_header_information
                .increase_header_start_offset(increase_by, layer);
        }
    }

    #[inline]
    fn decrease_header_start_offset(&mut self, decrease_by: usize, layer: Layer) {
        if layer != LAYER {
            self.header_start_offset -= decrease_by;
            self.previous_header_information
                .decrease_header_start_offset(decrease_by, layer);
        }
    }

    #[inline]
    fn header_length_mut(&mut self, layer: Layer) -> &mut usize {
        if layer == LAYER {
            &mut self.header_length
        } else {
            self.previous_header_information.header_length_mut(layer)
        }
    }

    #[inline]
    fn set_data_length(
        &mut self,
        data_length: usize,
        buffer_length: usize,
    ) -> Result<(), UnexpectedBufferEndError> {
        self.previous_header_information
            .set_data_length(data_length, buffer_length)
    }
}

impl<B, PHI> Payload for DataBuffer<B, Ieee802_1QVlan<PHI>>
where
    B: AsRef<[u8]>,
    PHI: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn payload(&self) -> &[u8] {
        let payload_start = self.header_length(LAYER);
        &self.data_buffer_starting_at_header(LAYER)[payload_start..]
    }

    #[inline]
    fn payload_length(&self) -> usize {
        self.payload().len()
    }
}

impl<B, PHI> PayloadMut for DataBuffer<B, Ieee802_1QVlan<PHI>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    PHI: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn payload_mut(&mut self) -> &mut [u8] {
        let payload_start = self.header_length(LAYER);
        &mut self.data_buffer_starting_at_header_mut(LAYER)[payload_start..]
    }
}

#[cfg(test)]
mod tests {
    use crate::data_buffer;
    use crate::data_buffer::traits::HeaderInformation;
    use crate::data_buffer::{DataBuffer, Payload, PayloadMut};
    use crate::error::{NotEnoughHeadroomError, UnexpectedBufferEndError};
    use crate::ethernet::{Eth, EthernetMethods};
    use crate::ieee802_1q_vlan::{
        Ieee802_1QMethods, Ieee802_1QMethodsMut, Ieee802_1QVlan, NotDoubleTaggedError,
        ParseIeee802_1QError, STagWithoutCTagError, LAYER,
    };
    use crate::no_previous_header::NoPreviousHeaderInformation;
    use crate::test_utils::copy_into_slice;
    use crate::typed_protocol_headers::EtherType;
    use crate::vlan::Vlan;

    const ETHERNET_SINGLE_TAGGED: [u8; 20] = [
        0x01, 0x80, 0x41, 0xAE, 0xFD, 0x7E, // Dst
        0x7E, 0xFD, 0xAE, 0x41, 0x80, 0x00, // Src
        0x81, 0x00, // Ether type
        0x5A, 0x8D, // C tag control information
        0x08, 0x00, // Ether type
        0xFF, 0xFF,
    ];

    const ETHERNET_DOUBLE_TAGGED: [u8; 24] = [
        0x01, 0x80, 0x41, 0xAE, 0xFD, 0x7E, // Dst
        0x7E, 0xFD, 0xAE, 0x41, 0x80, 0x00, // Src
        0x88, 0xA8, // Ether type
        0x8A, 0xAD, // S tag control information
        0x81, 0x00, // C tag
        0x5A, 0x8D, // C tag control information
        0x08, 0x00, // Ether type
        0xFF, 0xFF,
    ];

    const SINGLE_TAGGED: [u8; 6] = [
        0x5A, 0x8D, // C tag control information
        0x08, 0x00, // Ether type
        0xFF, 0xFF,
    ];

    const DOUBLE_TAGGED: [u8; 10] = [
        0x8A, 0xAD, // S tag control information
        0x81, 0x00, // C tag
        0x5A, 0x8D, // C tag control information
        0x08, 0x00, // Ether type
        0xFF, 0xFF,
    ];

    #[test]
    fn new_single_tagged() {
        assert!(
            DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
                SINGLE_TAGGED,
                0,
                Vlan::SingleTagged,
            )
            .is_ok()
        );
    }

    #[test]
    fn new_single_tagged_data_buffer_too_short() {
        assert_eq!(
            Err(ParseIeee802_1QError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 4,
                    actual_length: 3,
                }
            )),
            DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
                &SINGLE_TAGGED[..3],
                0,
                Vlan::SingleTagged,
            )
        );
    }

    #[test]
    fn new_single_tagged_data_offset_out_of_range() {
        assert_eq!(
            Err(ParseIeee802_1QError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: SINGLE_TAGGED.len() + 1,
                    actual_length: SINGLE_TAGGED.len(),
                }
            )),
            DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
                &SINGLE_TAGGED,
                SINGLE_TAGGED.len() + 1,
                Vlan::SingleTagged,
            )
        );
    }

    #[test]
    fn new_double_tagged() {
        assert!(
            DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
                DOUBLE_TAGGED,
                0,
                Vlan::DoubleTagged,
            )
            .is_ok()
        );
    }

    #[test]
    fn new_double_tagged_no_c_tag_identifier() {
        let mut data = DOUBLE_TAGGED;
        data[3] = 1;
        assert_eq!(
            Err(ParseIeee802_1QError::STagWithoutCTag(STagWithoutCTagError)),
            DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
                &data,
                0,
                Vlan::DoubleTagged,
            )
        );
    }

    #[test]
    fn new_double_tagged_data_buffer_too_short() {
        assert_eq!(
            Err(ParseIeee802_1QError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 8,
                    actual_length: 7,
                }
            )),
            DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
                &DOUBLE_TAGGED[..7],
                0,
                Vlan::DoubleTagged,
            )
        );
    }

    #[test]
    fn new_double_tagged_data_offset_out_of_range() {
        assert_eq!(
            Err(ParseIeee802_1QError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: DOUBLE_TAGGED.len() + 1,
                    actual_length: DOUBLE_TAGGED.len(),
                }
            )),
            DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
                &DOUBLE_TAGGED,
                DOUBLE_TAGGED.len() + 1,
                Vlan::DoubleTagged,
            )
        );
    }

    #[test]
    fn single_tagged_ieee802_1q_c_tag_control_information() {
        let single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(
            [0x5A, 0x8D],
            single_tagged.ieee802_1q_c_tag_control_information()
        );
    }

    #[test]
    fn double_tagged_ieee802_1q_c_tag_control_information() {
        let double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(
            [0x5A, 0x8D],
            double_tagged.ieee802_1q_c_tag_control_information()
        );
    }

    #[test]
    fn single_tagged_ieee802_1q_c_tag_priority_code_point() {
        let single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(2, single_tagged.ieee802_1q_c_tag_priority_code_point());
    }

    #[test]
    fn double_tagged_ieee802_1q_c_tag_priority_code_point() {
        let double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(2, double_tagged.ieee802_1q_c_tag_priority_code_point());
    }

    #[test]
    fn single_tagged_ieee802_1q_c_tag_drop_eligible_indicator() {
        let single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert!(single_tagged.ieee802_1q_c_tag_drop_eligible_indicator());
    }

    #[test]
    fn double_tagged_ieee802_1q_c_tag_drop_eligible_indicator() {
        let double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert!(double_tagged.ieee802_1q_c_tag_drop_eligible_indicator());
    }

    #[test]
    fn single_tagged_ieee802_1q_c_tag_vlan_identifier() {
        let single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(0xA8D, single_tagged.ieee802_1q_c_tag_vlan_identifier());
    }

    #[test]
    fn double_tagged_ieee802_1q_c_tag_vlan_identifier() {
        let double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(0xA8D, double_tagged.ieee802_1q_c_tag_vlan_identifier());
    }

    #[test]
    fn single_tagged_ieee802_1q_s_tag_control_information() {
        let single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(None, single_tagged.ieee802_1q_s_tag_control_information());
    }

    #[test]
    fn double_tagged_ieee802_1q_s_tag_control_information() {
        let double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(
            Some([0x8A, 0xAD]),
            double_tagged.ieee802_1q_s_tag_control_information()
        );
    }

    #[test]
    fn single_tagged_ieee802_1q_s_tag_priority_code_point() {
        let single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(None, single_tagged.ieee802_1q_s_tag_priority_code_point());
    }

    #[test]
    fn double_tagged_ieee802_1q_s_tag_priority_code_point() {
        let double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(
            Some(4),
            double_tagged.ieee802_1q_s_tag_priority_code_point()
        );
    }

    #[test]
    fn single_tagged_ieee802_1q_s_tag_drop_eligible_indicator() {
        let single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(
            None,
            single_tagged.ieee802_1q_s_tag_drop_eligible_indicator()
        );
    }

    #[test]
    fn double_tagged_ieee802_1q_s_tag_drop_eligible_indicator() {
        let double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(
            Some(false),
            double_tagged.ieee802_1q_s_tag_drop_eligible_indicator()
        );
    }

    #[test]
    fn single_tagged_ieee802_1q_s_tag_vlan_identifier() {
        let single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(None, single_tagged.ieee802_1q_s_tag_vlan_identifier());
    }

    #[test]
    fn double_tagged_ieee802_1q_s_tag_vlan_identifier() {
        let double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(
            Some(0xAAD),
            double_tagged.ieee802_1q_s_tag_vlan_identifier()
        );
    }

    #[test]
    fn single_tagged_ieee802_1q_typed_vlan() {
        let single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(Vlan::SingleTagged, single_tagged.ieee802_1q_typed_vlan());
    }

    #[test]
    fn double_tagged_ieee802_1q_typed_vlan() {
        let double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(Vlan::DoubleTagged, double_tagged.ieee802_1q_typed_vlan());
    }

    #[test]
    fn single_tagged_ieee802_1q_ether_type() {
        let single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(0x800, single_tagged.ieee802_1q_ether_type());
    }

    #[test]
    fn double_tagged_ieee802_1q_ether_type() {
        let double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(0x800, double_tagged.ieee802_1q_ether_type());
    }

    #[test]
    fn single_tagged_ieee802_1q_typed_ether_type() {
        let single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(
            Ok(EtherType::Ipv4),
            single_tagged.ieee802_1q_typed_ether_type()
        );
    }

    #[test]
    fn double_tagged_ieee802_1q_typed_ether_type() {
        let double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            &DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(
            Ok(EtherType::Ipv4),
            double_tagged.ieee802_1q_typed_ether_type()
        );
    }

    #[test]
    fn single_tagged_set_ieee802_1q_c_tag_control_information() {
        let mut single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        single_tagged.set_ieee802_1q_c_tag_control_information(&[0xAA, 0xAA]);
        assert_eq!(
            [0xAA, 0xAA],
            single_tagged.ieee802_1q_c_tag_control_information()
        );
    }

    #[test]
    fn double_tagged_set_ieee802_1q_c_tag_control_information() {
        let mut double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        double_tagged.set_ieee802_1q_c_tag_control_information(&[0xAA, 0xAA]);
        assert_eq!(
            [0xAA, 0xAA],
            double_tagged.ieee802_1q_c_tag_control_information()
        );
    }

    #[test]
    fn single_tagged_set_ieee802_1q_c_tag_priority_code_point() {
        let mut single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        single_tagged.set_ieee802_1q_c_tag_priority_code_point(5);
        assert_eq!(5, single_tagged.ieee802_1q_c_tag_priority_code_point());
    }

    #[test]
    fn double_tagged_set_ieee802_1q_c_tag_priority_code_point() {
        let mut double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        double_tagged.set_ieee802_1q_c_tag_priority_code_point(5);
        assert_eq!(5, double_tagged.ieee802_1q_c_tag_priority_code_point());
    }

    #[test]
    fn single_tagged_set_ieee802_1q_c_tag_drop_eligible_indicator() {
        let mut single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert!(single_tagged.ieee802_1q_c_tag_drop_eligible_indicator());
        single_tagged.set_ieee802_1q_c_tag_drop_eligible_indicator(false);
        assert!(!single_tagged.ieee802_1q_c_tag_drop_eligible_indicator());
    }

    #[test]
    fn double_tagged_set_ieee802_1q_c_tag_drop_eligible_indicator() {
        let mut double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert!(double_tagged.ieee802_1q_c_tag_drop_eligible_indicator());
        double_tagged.set_ieee802_1q_c_tag_drop_eligible_indicator(false);
        assert!(!double_tagged.ieee802_1q_c_tag_drop_eligible_indicator());
    }

    #[test]
    fn single_tagged_set_ieee802_1q_c_tag_vlan_identifier() {
        let mut single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(0xA8D, single_tagged.ieee802_1q_c_tag_vlan_identifier());
        single_tagged.set_ieee802_1q_c_tag_vlan_identifier(0xFFF);
        assert_eq!(0xFFF, single_tagged.ieee802_1q_c_tag_vlan_identifier());
    }

    #[test]
    fn double_tagged_set_ieee802_1q_c_tag_vlan_identifier() {
        let mut double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(0xA8D, double_tagged.ieee802_1q_c_tag_vlan_identifier());
        double_tagged.set_ieee802_1q_c_tag_vlan_identifier(0xFFF);
        assert_eq!(0xFFF, double_tagged.ieee802_1q_c_tag_vlan_identifier());
    }

    #[test]
    fn single_tagged_add_or_update_ieee802_1q_s_tag() {
        let mut data = [0_u8; 50];
        copy_into_slice(&mut data, &SINGLE_TAGGED, 38);
        let mut single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            data,
            38,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(None, single_tagged.ieee802_1q_s_tag_control_information());
        assert!(single_tagged
            .add_or_update_ieee802_1q_s_tag(&[0xBB, 0xBB])
            .is_ok());
        assert_eq!(
            Some([0xBB, 0xBB]),
            single_tagged.ieee802_1q_s_tag_control_information()
        );

        let mut data = [0_u8; 50];
        copy_into_slice(&mut data, &ETHERNET_SINGLE_TAGGED, 4);
        let mut single_tagged = DataBuffer::<_, Ieee802_1QVlan<Eth>>::new_from_lower(
            DataBuffer::<_, Eth>::new(data, 4).unwrap(),
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(None, single_tagged.ieee802_1q_s_tag_control_information());
        assert!(single_tagged
            .add_or_update_ieee802_1q_s_tag(&[0xBB, 0xBB])
            .is_ok());
        assert_eq!(
            Some([0xBB, 0xBB]),
            single_tagged.ieee802_1q_s_tag_control_information()
        );
        assert_eq!(
            EtherType::ServiceTag as u16,
            single_tagged.ethernet_ether_type()
        );
        assert_eq!(Vlan::DoubleTagged, single_tagged.ieee802_1q_typed_vlan());
        assert_eq!(0, single_tagged.headroom_internal());
        let _ = DataBuffer::<_, Ieee802_1QVlan<Eth>>::new_from_lower(
            DataBuffer::<_, Eth>::new(
                data_buffer::BufferIntoInner::buffer_into_inner(single_tagged),
                0,
            )
            .unwrap(),
            Vlan::DoubleTagged,
        )
        .unwrap();
    }

    #[test]
    fn single_tagged_add_or_update_ieee802_1q_s_tag_no_headroom() {
        let mut single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(None, single_tagged.ieee802_1q_s_tag_control_information());
        assert_eq!(
            Err(NotEnoughHeadroomError {
                required: 4,
                available: 0
            }),
            single_tagged.add_or_update_ieee802_1q_s_tag(&[0xBB, 0xBB])
        );

        let mut data = [0_u8; 50];
        copy_into_slice(&mut data, &SINGLE_TAGGED, 3);
        let mut single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            data,
            3,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(None, single_tagged.ieee802_1q_s_tag_control_information());
        assert_eq!(
            Err(NotEnoughHeadroomError {
                required: 4,
                available: 3
            }),
            single_tagged.add_or_update_ieee802_1q_s_tag(&[0xBB, 0xBB])
        );
    }

    #[test]
    fn double_tagged_add_or_update_ieee802_1q_s_tag() {
        let mut double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(
            Some([0x8A, 0xAD]),
            double_tagged.ieee802_1q_s_tag_control_information()
        );
        assert!(double_tagged
            .add_or_update_ieee802_1q_s_tag(&[0xBB, 0xBB])
            .is_ok());
        assert_eq!(
            Some([0xBB, 0xBB]),
            double_tagged.ieee802_1q_s_tag_control_information()
        );
    }

    #[test]
    fn single_tagged_set_ieee802_1q_s_tag_priority_code_point() {
        let mut single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(
            Err(NotDoubleTaggedError),
            single_tagged.set_ieee802_1q_s_tag_priority_code_point(1)
        );
    }

    #[test]
    fn double_tagged_set_ieee802_1q_s_tag_priority_code_point() {
        let mut double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(
            Some(4),
            double_tagged.ieee802_1q_s_tag_priority_code_point()
        );
        assert!(double_tagged
            .set_ieee802_1q_s_tag_priority_code_point(5)
            .is_ok());
        assert_eq!(
            Some(5),
            double_tagged.ieee802_1q_s_tag_priority_code_point()
        );
    }

    #[test]
    fn single_tagged_set_ieee802_1q_s_tag_drop_eligible_indicator() {
        let mut single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(
            Err(NotDoubleTaggedError),
            single_tagged.set_ieee802_1q_s_tag_drop_eligible_indicator(false)
        );
    }

    #[test]
    fn double_tagged_set_ieee802_1q_s_tag_drop_eligible_indicator() {
        let mut double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(
            Some(false),
            double_tagged.ieee802_1q_s_tag_drop_eligible_indicator()
        );
        assert!(double_tagged
            .set_ieee802_1q_s_tag_drop_eligible_indicator(true)
            .is_ok());
        assert_eq!(
            Some(true),
            double_tagged.ieee802_1q_s_tag_drop_eligible_indicator()
        );
    }

    #[test]
    fn single_tagged_set_ieee802_1q_s_tag_vlan_identifier() {
        let mut single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(
            Err(NotDoubleTaggedError),
            single_tagged.set_ieee802_1q_s_tag_vlan_identifier(0xFFF)
        );
    }

    #[test]
    fn double_tagged_set_ieee802_1q_s_tag_vlan_identifier() {
        let mut double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(
            Some(0xAAD),
            double_tagged.ieee802_1q_s_tag_vlan_identifier()
        );
        assert!(double_tagged
            .set_ieee802_1q_s_tag_vlan_identifier(0xFFF)
            .is_ok());
        assert_eq!(
            Some(0xFFF),
            double_tagged.ieee802_1q_s_tag_vlan_identifier()
        );
    }

    #[test]
    fn single_tagged_cut_ieee802_1q_s_tag() {
        let mut single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();

        single_tagged.cut_ieee802_1q_s_tag();
    }

    #[test]
    fn double_tagged_cut_ieee802_1q_s_tag() {
        let mut double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(8, double_tagged.header_length(LAYER));
        assert_eq!(Vlan::DoubleTagged, double_tagged.ieee802_1q_typed_vlan());
        double_tagged.cut_ieee802_1q_s_tag();
        assert_eq!(4, double_tagged.header_length(LAYER));
        assert_eq!(Vlan::SingleTagged, double_tagged.ieee802_1q_typed_vlan());
        let headroom = double_tagged.headroom_internal();
        assert_eq!(
            DOUBLE_TAGGED[4..],
            data_buffer::BufferIntoInner::buffer_into_inner(double_tagged)[headroom..]
        );

        let mut double_tagged = DataBuffer::<_, Ieee802_1QVlan<Eth>>::new_from_lower(
            DataBuffer::<_, Eth>::new(ETHERNET_DOUBLE_TAGGED, 0).unwrap(),
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(8, double_tagged.header_length(LAYER));
        assert_eq!(Vlan::DoubleTagged, double_tagged.ieee802_1q_typed_vlan());
        assert_eq!(
            EtherType::ServiceTag as u16,
            double_tagged.ethernet_ether_type()
        );
        double_tagged.cut_ieee802_1q_s_tag();
        assert_eq!(
            EtherType::CustomerTag as u16,
            double_tagged.ethernet_ether_type()
        );
        assert_eq!(4, double_tagged.header_length(LAYER));
        assert_eq!(Vlan::SingleTagged, double_tagged.ieee802_1q_typed_vlan());
        let headroom = double_tagged.headroom_internal() + double_tagged.header_start_offset(LAYER);
        assert_eq!(
            DOUBLE_TAGGED[4..],
            data_buffer::BufferIntoInner::buffer_into_inner(double_tagged)[headroom..]
        );
    }

    #[test]
    fn single_tagged_set_ieee802_1q_ether_type() {
        let mut single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(
            Ok(EtherType::Ipv4),
            single_tagged.ieee802_1q_typed_ether_type()
        );
        single_tagged.set_ieee802_1q_ether_type(EtherType::Ipv6 as u16);
        assert_eq!(
            Ok(EtherType::Ipv6),
            single_tagged.ieee802_1q_typed_ether_type()
        );
    }

    #[test]
    fn double_tagged_set_ieee802_1q_ether_type() {
        let mut double_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            DOUBLE_TAGGED,
            0,
            Vlan::DoubleTagged,
        )
        .unwrap();
        assert_eq!(
            Ok(EtherType::Ipv4),
            double_tagged.ieee802_1q_typed_ether_type()
        );
        double_tagged.set_ieee802_1q_ether_type(EtherType::Ipv6 as u16);
        assert_eq!(
            Ok(EtherType::Ipv6),
            double_tagged.ieee802_1q_typed_ether_type()
        );
    }

    #[test]
    fn payload() {
        let single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(&[0xFF, 0xFF,], single_tagged.payload());
    }

    #[test]
    fn payload_length() {
        let single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();
        assert_eq!(2, single_tagged.payload_length());
    }

    #[test]
    fn payload_mut() {
        let mut single_tagged = DataBuffer::<_, Ieee802_1QVlan<NoPreviousHeaderInformation>>::new(
            SINGLE_TAGGED,
            0,
            Vlan::SingleTagged,
        )
        .unwrap();

        assert_eq!(&[0xFF, 0xFF,], single_tagged.payload_mut());
    }
}
