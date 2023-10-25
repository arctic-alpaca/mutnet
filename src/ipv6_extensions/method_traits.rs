use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderInformation, HeaderManipulation, Layer,
};
use crate::internet_protocol::InternetProtocolNumber;
use crate::ipv6::UpdateIpv6Length;
use crate::ipv6_extensions::metadata_trait::{Ipv6ExtMetaData, Ipv6ExtMetaDataMut};
use crate::ipv6_extensions::routing_types::RoutingType;
use crate::ipv6_extensions::{
    Ipv6ExtFieldError, Ipv6ExtSetFieldError, Ipv6ExtTypedHeader, Ipv6Extension,
    Ipv6ExtensionIndexOutOfBoundsError,
};
use core::cmp::Ordering;

pub(crate) static NEXT_HEADER: usize = 0;
pub(crate) static EXTENSION_MIN_LEN: usize = 8;

mod shared_dest_opt_hop_by_hop_routing {
    pub(crate) static LENGTH: usize = 1;
}

mod dest_opt_and_hop_by_hop {
    pub(crate) static DATA_START: usize = 2;
}

mod routing {
    pub(crate) static ROUTING_TYPE: usize = 2;
    pub(crate) static SEGMENTS_LEFT: usize = 3;
    pub(crate) static DATA_START: usize = 4;
}

mod fragment {
    use core::ops::Range;

    pub(crate) static FRAGMENT_OFFSET: Range<usize> = 2..4;
    pub(crate) static FRAGMENT_OFFSET_SHIFT: usize = 3;
    pub(crate) static MORE_FRAGMENTS_BYTE: usize = 3;
    pub(crate) static MORE_FRAGMENTS_MASK: u8 = 0b0000_0001;
    pub(crate) static IDENTIFICATION: Range<usize> = 4..8;
}

pub(crate) static LAYER: Layer = Layer::Ipv6Ext;

// Length manipulating methods:
// - set_ipv6_ext_length (has proof)

pub trait Ipv6ExtMethods<const MAX_EXTENSIONS: usize>:
    HeaderInformation + BufferAccess + Ipv6ExtMetaData<MAX_EXTENSIONS>
{
    #[inline]
    fn ipv6_ext_amount(&self) -> usize {
        self.extensions_amount()
    }

    #[inline]
    fn ipv6_extensions(&self) -> [Ipv6Extension; MAX_EXTENSIONS] {
        let mut result = [Ipv6Extension::HopByHop; MAX_EXTENSIONS];
        self.extensions()[..self.extensions_amount()]
            .iter()
            .enumerate()
            .for_each(|(i, ext)| result[i] = ext.ext_type);
        result
    }

    #[inline]
    fn ipv6_ext_next_header(&self) -> Result<u8, Ipv6ExtensionIndexOutOfBoundsError> {
        let extension_metadata = self.extension(self.extensions_amount() - 1)?;
        Ok(self.data_buffer_starting_at_header(LAYER)[extension_metadata.offset + NEXT_HEADER])
    }

    #[inline]
    fn ipv6_ext_typed_next_header(&self) -> Result<InternetProtocolNumber, Ipv6ExtTypedHeader> {
        let extension_metadata = self.extension(self.extensions_amount() - 1)?;
        Ok(
            self.data_buffer_starting_at_header(LAYER)[extension_metadata.offset + NEXT_HEADER]
                .try_into()?,
        )
    }

    #[inline]
    fn ipv6_ext_per_extension_next_header(
        &self,
        extension_index: usize,
    ) -> Result<u8, Ipv6ExtensionIndexOutOfBoundsError> {
        let extension_metadata = self.extension(extension_index)?;
        Ok(self.data_buffer_starting_at_header(LAYER)[extension_metadata.offset + NEXT_HEADER])
    }

    #[inline]
    fn ipv6_ext_per_extension_typed_next_header(
        &self,
        extension_index: usize,
    ) -> Result<InternetProtocolNumber, Ipv6ExtTypedHeader> {
        let extension_metadata = self.extension(extension_index)?;
        Ok(
            self.data_buffer_starting_at_header(LAYER)[extension_metadata.offset + NEXT_HEADER]
                .try_into()?,
        )
    }

    /// Routing, destination options, hop by hop
    #[inline]
    fn ipv6_ext_length(&self, extension_index: usize) -> Result<u8, Ipv6ExtFieldError> {
        let extension_metadata = self.extension(extension_index)?;
        match extension_metadata.ext_type {
            Ipv6Extension::Fragment => Err(Ipv6ExtFieldError::FieldDoesNotExist),
            Ipv6Extension::DestinationOptions
            | Ipv6Extension::HopByHop
            | Ipv6Extension::Routing => Ok(self.data_buffer_starting_at_header(LAYER)
                [extension_metadata.offset + shared_dest_opt_hop_by_hop_routing::LENGTH]),
        }
    }

    #[inline]
    fn ipv6_ext_length_in_bytes(
        &self,
        extension_index: usize,
    ) -> Result<usize, Ipv6ExtensionIndexOutOfBoundsError> {
        let extension_metadata = self.extension(extension_index)?;
        match extension_metadata.ext_type {
            Ipv6Extension::Fragment => Ok(8),
            Ipv6Extension::DestinationOptions
            | Ipv6Extension::HopByHop
            | Ipv6Extension::Routing => Ok((usize::from(
                self.data_buffer_starting_at_header(LAYER)
                    [extension_metadata.offset + shared_dest_opt_hop_by_hop_routing::LENGTH],
            ) + 1)
                * 8),
        }
    }

    /// Routing, destination options, hop by hop
    #[inline]
    fn ipv6_ext_data(&self, extension_index: usize) -> Result<&[u8], Ipv6ExtFieldError> {
        let extension_metadata = self.extension(extension_index)?;
        let data_range = match extension_metadata.ext_type {
            Ipv6Extension::Fragment => return Err(Ipv6ExtFieldError::FieldDoesNotExist),
            Ipv6Extension::Routing => {
                let data_end = self.ipv6_ext_length_in_bytes(extension_index)?;
                extension_metadata.offset + routing::DATA_START
                    ..extension_metadata.offset + data_end
            }
            Ipv6Extension::DestinationOptions | Ipv6Extension::HopByHop => {
                let data_end = self.ipv6_ext_length_in_bytes(extension_index)?;
                extension_metadata.offset + dest_opt_and_hop_by_hop::DATA_START
                    ..extension_metadata.offset + data_end
            }
        };
        Ok(&self.data_buffer_starting_at_header(LAYER)[data_range])
    }

    /// Routing
    #[inline]
    fn ipv6_ext_routing_type(&self, extension_index: usize) -> Result<u8, Ipv6ExtFieldError> {
        let extension_metadata = self.extension(extension_index)?;
        match extension_metadata.ext_type {
            Ipv6Extension::Routing => Ok(self.data_buffer_starting_at_header(LAYER)
                [extension_metadata.offset + routing::ROUTING_TYPE]),
            Ipv6Extension::DestinationOptions
            | Ipv6Extension::HopByHop
            | Ipv6Extension::Fragment => Err(Ipv6ExtFieldError::FieldDoesNotExist),
        }
    }

    /// Routing
    #[inline]
    fn ipv6_ext_segments_left(&self, extension_index: usize) -> Result<u8, Ipv6ExtFieldError> {
        let extension_metadata = self.extension(extension_index)?;
        match extension_metadata.ext_type {
            Ipv6Extension::Routing => Ok(self.data_buffer_starting_at_header(LAYER)
                [extension_metadata.offset + routing::SEGMENTS_LEFT]),
            Ipv6Extension::DestinationOptions
            | Ipv6Extension::HopByHop
            | Ipv6Extension::Fragment => Err(Ipv6ExtFieldError::FieldDoesNotExist),
        }
    }

    /// Fragment
    #[inline]
    fn ipv6_ext_fragment_offset(&self, extension_index: usize) -> Result<u16, Ipv6ExtFieldError> {
        let extension_metadata = self.extension(extension_index)?;
        match extension_metadata.ext_type {
            Ipv6Extension::Fragment => Ok(u16::from_be_bytes(
                self.data_buffer_starting_at_header(LAYER)[extension_metadata.offset
                    + fragment::FRAGMENT_OFFSET.start
                    ..extension_metadata.offset + fragment::FRAGMENT_OFFSET.end]
                    .try_into()
                    .unwrap(),
            ) >> fragment::FRAGMENT_OFFSET_SHIFT),
            Ipv6Extension::DestinationOptions
            | Ipv6Extension::HopByHop
            | Ipv6Extension::Routing => Err(Ipv6ExtFieldError::FieldDoesNotExist),
        }
    }

    /// Fragment
    #[inline]
    fn ipv6_ext_more_fragments(&self, extension_index: usize) -> Result<bool, Ipv6ExtFieldError> {
        let extension_metadata = self.extension(extension_index)?;
        match extension_metadata.ext_type {
            Ipv6Extension::Fragment => Ok((self.data_buffer_starting_at_header(LAYER)
                [extension_metadata.offset + fragment::MORE_FRAGMENTS_BYTE]
                & fragment::MORE_FRAGMENTS_MASK)
                != 0),
            Ipv6Extension::DestinationOptions
            | Ipv6Extension::HopByHop
            | Ipv6Extension::Routing => Err(Ipv6ExtFieldError::FieldDoesNotExist),
        }
    }

    /// Fragment
    #[inline]
    fn ipv6_ext_fragment_identification(
        &self,
        extension_index: usize,
    ) -> Result<u32, Ipv6ExtFieldError> {
        let extension_metadata = self.extension(extension_index)?;
        match extension_metadata.ext_type {
            Ipv6Extension::Fragment => Ok(u32::from_be_bytes(
                self.data_buffer_starting_at_header(LAYER)[extension_metadata.offset
                    + fragment::IDENTIFICATION.start
                    ..extension_metadata.offset + fragment::IDENTIFICATION.end]
                    .try_into()
                    .unwrap(),
            )),
            Ipv6Extension::DestinationOptions
            | Ipv6Extension::HopByHop
            | Ipv6Extension::Routing => Err(Ipv6ExtFieldError::FieldDoesNotExist),
        }
    }
}

pub trait Ipv6ExtMethodsMut<const MAX_EXTENSIONS: usize>:
    HeaderInformation
    + HeaderManipulation
    + BufferAccessMut
    + Ipv6ExtMethods<MAX_EXTENSIONS>
    + Ipv6ExtMetaData<MAX_EXTENSIONS>
    + Ipv6ExtMetaDataMut<MAX_EXTENSIONS>
    + UpdateIpv6Length
    + Sized
{
    #[inline]
    fn set_ipv6_ext_next_header(
        &mut self,
        next_header: InternetProtocolNumber,
    ) -> Result<(), Ipv6ExtensionIndexOutOfBoundsError> {
        let extension_metadata = self.extension(self.extensions_amount() - 1)?;
        self.data_buffer_starting_at_header_mut(LAYER)[extension_metadata.offset + NEXT_HEADER] =
            next_header as u8;
        Ok(())
    }

    /// Routing, destination options, hop by hop
    #[inline]
    fn set_ipv6_ext_length(
        &mut self,
        new_length: u8,
        extension_index: usize,
    ) -> Result<(), Ipv6ExtSetFieldError> {
        let extension_metadata = self.extension(extension_index)?;

        match extension_metadata.ext_type {
            Ipv6Extension::Fragment => Err(Ipv6ExtSetFieldError::FieldDoesNotExist),
            Ipv6Extension::DestinationOptions
            | Ipv6Extension::HopByHop
            | Ipv6Extension::Routing => {
                let new_length_in_bytes = (usize::from(new_length) + 1) * 8;
                let old_length_in_bytes = self.ipv6_ext_length_in_bytes(extension_index)?;

                match old_length_in_bytes.cmp(&new_length_in_bytes) {
                    Ordering::Less => {
                        let difference = new_length_in_bytes - old_length_in_bytes;
                        self.grow_header(
                            extension_metadata.offset + old_length_in_bytes,
                            difference,
                            LAYER,
                        )?;
                        let extensions_amount = self.extensions_amount();
                        self.extensions_mut()[extension_index + 1..extensions_amount]
                            .iter_mut()
                            .for_each(|extension_metadata| {
                                extension_metadata.offset += difference;
                            });
                    }
                    Ordering::Equal => return Ok(()),
                    Ordering::Greater => {
                        let difference = old_length_in_bytes - new_length_in_bytes;
                        self.shrink_header(
                            extension_metadata.offset + new_length_in_bytes,
                            difference,
                            LAYER,
                        );
                        let extensions_amount = self.extensions_amount();
                        self.extensions_mut()[extension_index + 1..extensions_amount]
                            .iter_mut()
                            .for_each(|extension_metadata| {
                                extension_metadata.offset -= difference;
                            });
                    }
                }

                self.update_ipv6_length();
                self.data_buffer_starting_at_header_mut(LAYER)
                    [extension_metadata.offset + shared_dest_opt_hop_by_hop_routing::LENGTH] =
                    new_length;
                Ok(())
            }
        }
    }

    /// Routing, destination options, hop by hop
    #[inline]
    fn ipv6_ext_data_mut(
        &mut self,
        extension_index: usize,
    ) -> Result<&mut [u8], Ipv6ExtFieldError> {
        let extension_metadata = self.extension(extension_index)?;
        let data_range = match extension_metadata.ext_type {
            Ipv6Extension::Fragment => return Err(Ipv6ExtFieldError::FieldDoesNotExist),
            Ipv6Extension::Routing => {
                let data_end = self.ipv6_ext_length_in_bytes(extension_index)?;
                extension_metadata.offset + routing::DATA_START
                    ..extension_metadata.offset + data_end
            }
            Ipv6Extension::DestinationOptions | Ipv6Extension::HopByHop => {
                let data_end = self.ipv6_ext_length_in_bytes(extension_index)?;
                extension_metadata.offset + dest_opt_and_hop_by_hop::DATA_START
                    ..extension_metadata.offset + data_end
            }
        };
        Ok(&mut self.data_buffer_starting_at_header_mut(LAYER)[data_range])
    }

    /// Routing
    #[inline]
    fn set_ipv6_ext_routing_type(
        &mut self,
        routing_type: RoutingType,
        extension_index: usize,
    ) -> Result<(), Ipv6ExtFieldError> {
        let extension_metadata = self.extension(extension_index)?;
        match extension_metadata.ext_type {
            Ipv6Extension::Routing => {
                self.data_buffer_starting_at_header_mut(LAYER)
                    [extension_metadata.offset + routing::ROUTING_TYPE] = routing_type as u8;
                Ok(())
            }
            Ipv6Extension::DestinationOptions
            | Ipv6Extension::HopByHop
            | Ipv6Extension::Fragment => Err(Ipv6ExtFieldError::FieldDoesNotExist),
        }
    }

    /// Routing
    #[inline]
    fn set_ipv6_ext_segments_left(
        &mut self,
        segments_left: u8,
        extension_index: usize,
    ) -> Result<(), Ipv6ExtFieldError> {
        let extension_metadata = self.extension(extension_index)?;
        match extension_metadata.ext_type {
            Ipv6Extension::Routing => {
                self.data_buffer_starting_at_header_mut(LAYER)
                    [extension_metadata.offset + routing::SEGMENTS_LEFT] = segments_left;
                Ok(())
            }
            Ipv6Extension::DestinationOptions
            | Ipv6Extension::HopByHop
            | Ipv6Extension::Fragment => Err(Ipv6ExtFieldError::FieldDoesNotExist),
        }
    }

    /// Fragment
    #[inline]
    fn set_ipv6_ext_fragment_offset(
        &mut self,
        fragment_offset: u16,
        extension_index: usize,
    ) -> Result<(), Ipv6ExtFieldError> {
        let extension_metadata = self.extension(extension_index)?;
        match extension_metadata.ext_type {
            Ipv6Extension::Fragment => {
                let fragment_offset = (fragment_offset << fragment::FRAGMENT_OFFSET_SHIFT)
                    | (self.data_buffer_starting_at_header(LAYER)[fragment::MORE_FRAGMENTS_BYTE]
                        & fragment::MORE_FRAGMENTS_MASK) as u16;

                self.data_buffer_starting_at_header_mut(LAYER)[extension_metadata.offset
                    + fragment::FRAGMENT_OFFSET.start
                    ..extension_metadata.offset + fragment::FRAGMENT_OFFSET.end]
                    .copy_from_slice(&fragment_offset.to_be_bytes());

                Ok(())
            }
            Ipv6Extension::DestinationOptions
            | Ipv6Extension::HopByHop
            | Ipv6Extension::Routing => Err(Ipv6ExtFieldError::FieldDoesNotExist),
        }
    }

    /// Fragment
    #[inline]
    fn set_ipv6_ext_more_fragments(
        &mut self,
        more_fragments: bool,
        extension_index: usize,
    ) -> Result<(), Ipv6ExtFieldError> {
        let extension_metadata = self.extension(extension_index)?;
        match extension_metadata.ext_type {
            Ipv6Extension::Fragment => {
                let byte_to_set = (self.data_buffer_starting_at_header(LAYER)
                    [fragment::MORE_FRAGMENTS_BYTE]
                    & !fragment::MORE_FRAGMENTS_MASK)
                    | u8::from(more_fragments);
                self.data_buffer_starting_at_header_mut(LAYER)
                    [extension_metadata.offset + fragment::MORE_FRAGMENTS_BYTE] = byte_to_set;

                Ok(())
            }
            Ipv6Extension::DestinationOptions
            | Ipv6Extension::HopByHop
            | Ipv6Extension::Routing => Err(Ipv6ExtFieldError::FieldDoesNotExist),
        }
    }

    /// Fragment
    #[inline]
    fn set_ipv6_ext_fragment_identification(
        &mut self,
        identification: u32,
        extension_index: usize,
    ) -> Result<(), Ipv6ExtFieldError> {
        let extension_metadata = self.extension(extension_index)?;
        match extension_metadata.ext_type {
            Ipv6Extension::Fragment => {
                self.data_buffer_starting_at_header_mut(LAYER)[extension_metadata.offset
                    + fragment::IDENTIFICATION.start
                    ..extension_metadata.offset + fragment::IDENTIFICATION.end]
                    .copy_from_slice(&identification.to_be_bytes());
                Ok(())
            }
            Ipv6Extension::DestinationOptions
            | Ipv6Extension::HopByHop
            | Ipv6Extension::Routing => Err(Ipv6ExtFieldError::FieldDoesNotExist),
        }
    }
}
