use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderInformation, HeaderManipulation, Layer,
};
use crate::error::NotEnoughHeadroomError;
use crate::ieee802_1q_vlan::NotDoubleTaggedError;
use crate::typed_protocol_headers::{EtherType, UnrecognizedEtherTypeError};
use crate::vlan::Vlan;
use core::ops::Range;

pub(crate) const SINGLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION: Range<usize> = 0..2;
pub(crate) const SINGLE_TAGGED_ETHER_TYPE: Range<usize> = 2..4;
pub(crate) const VLAN_S_TAG_CONTROL_INFORMATION: Range<usize> = 0..2;
pub(crate) const DOUBLE_TAGGED_C_TAG_INDICATOR: Range<usize> = 2..4;
pub(crate) const DOUBLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION: Range<usize> = 4..6;
pub(crate) const DOUBLE_TAGGED_ETHER_TYPE: Range<usize> = 6..8;
pub(crate) const PCP_SHIFT: usize = 5;
pub(crate) const PCP_MASK: u8 = 0b1110_0000;
pub(crate) const DEI_SHIFT: usize = 4;
pub(crate) const DEI_MASK: u8 = 0b0001_0000;
pub(crate) const VID_MASK: u16 = 0b0000_1111_1111_1111;
pub(crate) const VID_FIRST_BYTE_MASK: u8 = 0b0000_1111;

pub(crate) const HEADER_MIN_LEN_SINGLE_TAGGED: usize = 4;
pub(crate) const HEADER_MIN_LEN_DOUBLE_TAGGED: usize = 8;

pub(crate) const LAYER: Layer = Layer::Ieee802_1QVlan;

// Length manipulating methods:
// - add_or_update_ieee802_1q_s_tag (has proof)
// - cut_ieee802_1q_s_tag (has proof)

pub trait Ieee802_1QMethods: HeaderInformation + BufferAccess {
    #[inline]
    fn ieee802_1q_c_tag_control_information(&self) -> [u8; 2] {
        if self.header_length(LAYER) == HEADER_MIN_LEN_SINGLE_TAGGED {
            self.read_array(LAYER, SINGLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION)
        } else {
            self.read_array(LAYER, DOUBLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION)
        }
    }

    #[inline]
    fn ieee802_1q_c_tag_priority_code_point(&self) -> u8 {
        if self.header_length(LAYER) == HEADER_MIN_LEN_SINGLE_TAGGED {
            self.read_value(LAYER, SINGLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION.start) >> PCP_SHIFT
        } else {
            self.read_value(LAYER, DOUBLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION.start) >> PCP_SHIFT
        }
    }

    #[inline]
    fn ieee802_1q_c_tag_drop_eligible_indicator(&self) -> bool {
        if self.header_length(LAYER) == HEADER_MIN_LEN_SINGLE_TAGGED {
            ((self.read_value(LAYER, SINGLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION.start)
                & DEI_MASK)
                >> DEI_SHIFT)
                != 0
        } else {
            ((self.read_value(LAYER, DOUBLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION.start)
                & DEI_MASK)
                >> DEI_SHIFT)
                != 0
        }
    }

    #[inline]
    fn ieee802_1q_c_tag_vlan_identifier(&self) -> u16 {
        if self.header_length(LAYER) == HEADER_MIN_LEN_SINGLE_TAGGED {
            u16::from_be_bytes(self.read_array(LAYER, SINGLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION))
                & VID_MASK
        } else {
            u16::from_be_bytes(self.read_array(LAYER, DOUBLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION))
                & VID_MASK
        }
    }

    #[inline]
    fn ieee802_1q_s_tag_control_information(&self) -> Option<[u8; 2]> {
        if self.header_length(LAYER) == HEADER_MIN_LEN_DOUBLE_TAGGED {
            Some(self.read_array(LAYER, VLAN_S_TAG_CONTROL_INFORMATION))
        } else {
            None
        }
    }
    #[inline]
    fn ieee802_1q_s_tag_priority_code_point(&self) -> Option<u8> {
        if self.header_length(LAYER) == HEADER_MIN_LEN_DOUBLE_TAGGED {
            Some(self.read_value(LAYER, VLAN_S_TAG_CONTROL_INFORMATION.start) >> PCP_SHIFT)
        } else {
            None
        }
    }

    #[inline]
    fn ieee802_1q_s_tag_drop_eligible_indicator(&self) -> Option<bool> {
        if self.header_length(LAYER) == HEADER_MIN_LEN_DOUBLE_TAGGED {
            Some(
                ((self.read_value(LAYER, VLAN_S_TAG_CONTROL_INFORMATION.start) & DEI_MASK)
                    >> DEI_SHIFT)
                    != 0,
            )
        } else {
            None
        }
    }

    #[inline]
    fn ieee802_1q_s_tag_vlan_identifier(&self) -> Option<u16> {
        if self.header_length(LAYER) == HEADER_MIN_LEN_DOUBLE_TAGGED {
            Some(
                u16::from_be_bytes(self.read_array(LAYER, VLAN_S_TAG_CONTROL_INFORMATION))
                    & VID_MASK,
            )
        } else {
            None
        }
    }

    #[inline]
    fn ieee802_1q_typed_vlan(&self) -> Vlan {
        if self.header_length(LAYER) == HEADER_MIN_LEN_SINGLE_TAGGED {
            Vlan::SingleTagged
        } else {
            Vlan::DoubleTagged
        }
    }

    #[inline]
    fn ieee802_1q_ether_type(&self) -> u16 {
        if self.header_length(LAYER) == HEADER_MIN_LEN_SINGLE_TAGGED {
            u16::from_be_bytes(self.read_array(LAYER, SINGLE_TAGGED_ETHER_TYPE))
        } else {
            u16::from_be_bytes(self.read_array(LAYER, DOUBLE_TAGGED_ETHER_TYPE))
        }
    }

    #[inline]
    fn ieee802_1q_typed_ether_type(&self) -> Result<EtherType, UnrecognizedEtherTypeError> {
        self.ieee802_1q_ether_type().try_into()
    }
}

pub trait Ieee802_1QMethodsMut:
    HeaderInformation
    + Ieee802_1QMethods
    + HeaderManipulation
    + BufferAccessMut
    + UpdateEtherTypeBelowIeee802_1q
    + Sized
{
    #[inline]
    fn set_ieee802_1q_c_tag_control_information(&mut self, tag_control_information: &[u8; 2]) {
        if self.header_length(LAYER) == HEADER_MIN_LEN_SINGLE_TAGGED {
            self.write_slice(
                LAYER,
                SINGLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION,
                tag_control_information,
            );
        } else {
            self.write_slice(
                LAYER,
                DOUBLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION,
                tag_control_information,
            );
        }
    }

    /// only 3 bits, everything else is cut off
    #[inline]
    fn set_ieee802_1q_c_tag_priority_code_point(&mut self, mut priority_code_point: u8) {
        if self.header_length(LAYER) == HEADER_MIN_LEN_SINGLE_TAGGED {
            priority_code_point <<= PCP_SHIFT;
            priority_code_point |= self
                .read_value(LAYER, SINGLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION.start)
                & !PCP_MASK;
            self.write_value(
                LAYER,
                SINGLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION.start,
                priority_code_point,
            );
        } else {
            priority_code_point <<= PCP_SHIFT;
            priority_code_point |= self
                .read_value(LAYER, DOUBLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION.start)
                & !PCP_MASK;
            self.write_value(
                LAYER,
                DOUBLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION.start,
                priority_code_point,
            );
        }
    }

    #[inline]
    fn set_ieee802_1q_c_tag_drop_eligible_indicator(&mut self, drop_eligible_indicator: bool) {
        if self.header_length(LAYER) == HEADER_MIN_LEN_SINGLE_TAGGED {
            let mut drop_eligible_indicator = (drop_eligible_indicator as u8) << DEI_SHIFT;
            drop_eligible_indicator |= self
                .read_value(LAYER, SINGLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION.start)
                & !DEI_MASK;
            self.write_value(
                LAYER,
                SINGLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION.start,
                drop_eligible_indicator,
            );
        } else {
            let mut drop_eligible_indicator = (drop_eligible_indicator as u8) << DEI_SHIFT;
            drop_eligible_indicator |= self
                .read_value(LAYER, DOUBLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION.start)
                & !DEI_MASK;
            self.write_value(
                LAYER,
                DOUBLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION.start,
                drop_eligible_indicator,
            );
        }
    }

    /// Only 12 bits, everything else is cut off
    #[inline]
    fn set_ieee802_1q_c_tag_vlan_identifier(&mut self, mut vlan_identifier: u16) {
        if self.header_length(LAYER) == HEADER_MIN_LEN_SINGLE_TAGGED {
            vlan_identifier &= VID_MASK;
            vlan_identifier |= ((self
                .read_value(LAYER, SINGLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION.start)
                & !VID_FIRST_BYTE_MASK) as u16)
                << 8;
            self.write_slice(
                LAYER,
                SINGLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION,
                &vlan_identifier.to_be_bytes(),
            );
        } else {
            vlan_identifier &= VID_MASK;
            vlan_identifier |= ((self
                .read_value(LAYER, DOUBLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION.start)
                & !VID_FIRST_BYTE_MASK) as u16)
                << 8;
            self.write_slice(
                LAYER,
                DOUBLE_TAGGED_VLAN_C_TAG_CONTROL_INFORMATION,
                &vlan_identifier.to_be_bytes(),
            );
        }
    }

    /// Updates the lower layers ether type.
    #[inline]
    fn add_or_update_ieee802_1q_s_tag(
        &mut self,
        s_tag_control_information: &[u8; 2],
    ) -> Result<(), NotEnoughHeadroomError> {
        if self.header_length(LAYER) == HEADER_MIN_LEN_SINGLE_TAGGED {
            self.grow_header(0, 4, LAYER)?;
            self.write_slice(
                LAYER,
                DOUBLE_TAGGED_C_TAG_INDICATOR,
                &(EtherType::CustomerTag as u16).to_be_bytes(),
            );

            self.set_double_tagged();
        }
        self.write_slice(
            LAYER,
            VLAN_S_TAG_CONTROL_INFORMATION,
            s_tag_control_information,
        );
        Ok(())
    }

    #[inline]
    fn set_ieee802_1q_s_tag_priority_code_point(
        &mut self,
        mut priority_code_point: u8,
    ) -> Result<(), NotDoubleTaggedError> {
        if self.header_length(LAYER) == HEADER_MIN_LEN_DOUBLE_TAGGED {
            priority_code_point <<= PCP_SHIFT;
            priority_code_point |=
                self.read_value(LAYER, VLAN_S_TAG_CONTROL_INFORMATION.start) & !PCP_MASK;
            self.write_value(
                LAYER,
                VLAN_S_TAG_CONTROL_INFORMATION.start,
                priority_code_point,
            );
            Ok(())
        } else {
            Err(NotDoubleTaggedError)
        }
    }

    #[inline]
    fn set_ieee802_1q_s_tag_drop_eligible_indicator(
        &mut self,
        drop_eligible_indicator: bool,
    ) -> Result<(), NotDoubleTaggedError> {
        if self.header_length(LAYER) == HEADER_MIN_LEN_DOUBLE_TAGGED {
            let mut drop_eligible_indicator = (drop_eligible_indicator as u8) << DEI_SHIFT;
            drop_eligible_indicator |=
                self.read_value(LAYER, VLAN_S_TAG_CONTROL_INFORMATION.start) & !DEI_MASK;
            self.write_value(
                LAYER,
                VLAN_S_TAG_CONTROL_INFORMATION.start,
                drop_eligible_indicator,
            );

            Ok(())
        } else {
            Err(NotDoubleTaggedError)
        }
    }

    #[inline]
    fn set_ieee802_1q_s_tag_vlan_identifier(
        &mut self,
        mut vlan_identifier: u16,
    ) -> Result<(), NotDoubleTaggedError> {
        if self.header_length(LAYER) == HEADER_MIN_LEN_DOUBLE_TAGGED {
            vlan_identifier &= VID_MASK;
            vlan_identifier |= ((self.read_value(LAYER, VLAN_S_TAG_CONTROL_INFORMATION.start)
                & !VID_FIRST_BYTE_MASK) as u16)
                << 8;
            self.write_slice(
                LAYER,
                VLAN_S_TAG_CONTROL_INFORMATION,
                &vlan_identifier.to_be_bytes(),
            );
            Ok(())
        } else {
            Err(NotDoubleTaggedError)
        }
    }

    /// Updates the lower layers ether type.
    #[inline]
    fn cut_ieee802_1q_s_tag(&mut self) {
        if self.header_length(LAYER) == HEADER_MIN_LEN_DOUBLE_TAGGED {
            self.shrink_header(0, 4, LAYER);
            self.set_single_tagged();
        }
    }

    #[inline]
    fn set_ieee802_1q_ether_type(&mut self, ether_type: u16) {
        if self.header_length(LAYER) == HEADER_MIN_LEN_SINGLE_TAGGED {
            self.write_slice(LAYER, SINGLE_TAGGED_ETHER_TYPE, &ether_type.to_be_bytes());
        } else {
            self.write_slice(LAYER, DOUBLE_TAGGED_ETHER_TYPE, &ether_type.to_be_bytes());
        }
    }
}

pub(crate) trait UpdateEtherTypeBelowIeee802_1q {
    fn set_single_tagged(&mut self);
    fn set_double_tagged(&mut self);
}
