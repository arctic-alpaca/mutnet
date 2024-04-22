//! IPv6 extensions implementation and IPv6 extensions specific errors.

pub use error::*;
pub(crate) use metadata_trait::{Ipv6ExtMetaData, Ipv6ExtMetaDataMut};
pub use method_traits::*;

use crate::data_buffer::traits::HeaderMetadataExtraction;
use crate::data_buffer::traits::{
    BufferAccess, BufferAccessMut, HeaderMetadata, HeaderMetadataMut, Layer,
};
use crate::data_buffer::{
    BufferIntoInner, DataBuffer, EthernetMarker, Ieee802_1QVlanMarker, Ipv6ExtMarker, Ipv6Marker,
    Payload, PayloadMut,
};
use crate::error::{LengthExceedsAvailableSpaceError, UnexpectedBufferEndError};
use crate::internal_utils::header_start_offset_from_phi;
use crate::ipv6::UpdateIpv6Length;
use crate::no_previous_header::NoPreviousHeader;
use crate::typed_protocol_headers::constants;
use crate::typed_protocol_headers::Ipv6ExtensionType;

#[cfg(all(feature = "remove_checksum", feature = "verify_ipv6_extensions", kani))]
mod verification;

mod error;
mod metadata_trait;
mod method_traits;

/// Metadata of a single extension header.
#[derive(Eq, PartialEq, Hash, Copy, Clone, Debug)]
pub struct Ipv6ExtensionMetadata {
    /// Offset from the start of the layer.
    pub offset: usize,
    /// Type of the extension.
    pub ext_type: Ipv6ExtensionType,
}

impl Default for Ipv6ExtensionMetadata {
    #[inline]
    fn default() -> Self {
        Self {
            offset: 0,
            ext_type: Ipv6ExtensionType::HopByHop,
        }
    }
}

impl Ipv6ExtensionMetadata {
    #[inline]
    pub(crate) fn new_typed_ext_type(offset: usize, ext_type: Ipv6ExtensionType) -> Self {
        Self { offset, ext_type }
    }
}

/// IPv6 extensions metadata.
///
/// Contains metadata about the IPv6 extensions headers in the parsed data buffer.
#[allow(private_bounds)]
#[derive(Eq, PartialEq, Hash, Copy, Clone, Debug)]
pub struct Ipv6Extensions<PHM, const MAX_EXTENSIONS: usize>
where
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    /// Offset from the start of the non-headroom part of the data buffer.
    header_start_offset: usize,
    /// Header length.
    header_length: usize,
    /// Metadata of the previous header(s).
    previous_header_metadata: PHM,
    /// Extensions metadata.
    extensions: [Ipv6ExtensionMetadata; MAX_EXTENSIONS],
    /// Amount of extensions.
    extensions_amount: usize,
}

impl<PHM, const MAX_EXTENSIONS: usize> Ipv6ExtMarker<MAX_EXTENSIONS>
    for Ipv6Extensions<PHM, MAX_EXTENSIONS>
where
    PHM: HeaderMetadata + HeaderMetadataMut,
{
}
impl<PHM, const MAX_EXTENSIONS: usize> EthernetMarker for Ipv6Extensions<PHM, MAX_EXTENSIONS> where
    PHM: HeaderMetadata + HeaderMetadataMut + EthernetMarker
{
}

impl<PHM, const MAX_EXTENSIONS: usize> Ieee802_1QVlanMarker for Ipv6Extensions<PHM, MAX_EXTENSIONS> where
    PHM: HeaderMetadata + HeaderMetadataMut + Ieee802_1QVlanMarker
{
}

impl<PHM, const MAX_EXTENSIONS: usize> Ipv6Marker for Ipv6Extensions<PHM, MAX_EXTENSIONS> where
    PHM: HeaderMetadata + HeaderMetadataMut + Ipv6Marker
{
}

#[allow(private_bounds)]
impl<B, PHM, const MAX_EXTENSIONS: usize> DataBuffer<B, Ipv6Extensions<PHM, MAX_EXTENSIONS>>
where
    B: AsRef<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut + Copy,
{
    /// Parses `buf` and creates a new [`DataBuffer`] for an IPv6 extensions layer with no previous layers.
    ///
    /// `headroom` indicates the amount of headroom in the provided `buf`.
    ///
    /// The returned boolean indicates whether the payload is fragmented.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided data buffer is shorter than expected.
    /// - more extensions than `MAX_EXTENSIONS` are present.
    /// - an unrecognized extension type is passed to the constructor of [`Ipv6Extensions`] (this
    /// constitutes a bug).
    #[inline]
    pub fn parse_ipv6_extensions_alone(
        buf: B,
        headroom: usize,
        next_header_byte: Ipv6ExtensionType,
    ) -> Result<
        (
            DataBuffer<B, Ipv6Extensions<NoPreviousHeader, MAX_EXTENSIONS>>,
            bool,
        ),
        ParseIpv6ExtensionsError,
    > {
        let lower_layer_data_buffer = DataBuffer::<B, NoPreviousHeader>::new(buf, headroom)?;

        DataBuffer::<B, Ipv6Extensions<NoPreviousHeader, MAX_EXTENSIONS>>::parse_ipv6_extensions_layer(
            lower_layer_data_buffer,
            next_header_byte,
        )
    }

    /// Consumes the `lower_layer_data_buffer` and creates a new [`DataBuffer`] with an additional
    /// IPv6 extensions layer.
    ///
    /// The returned boolean indicates whether the payload is fragmented.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided data buffer is shorter than expected.
    /// - more extensions than `MAX_EXTENSIONS` are present.
    /// - an unrecognized extension type is passed to the constructor of [`Ipv6Extensions`] (this
    /// constitutes a bug).
    #[inline]
    pub fn parse_ipv6_extensions_layer(
        lower_layer_data_buffer: impl HeaderMetadata
            + Payload
            + BufferIntoInner<B>
            + HeaderMetadataExtraction<PHM>,
        first_extension: Ipv6ExtensionType,
    ) -> Result<(DataBuffer<B, Ipv6Extensions<PHM, MAX_EXTENSIONS>>, bool), ParseIpv6ExtensionsError>
    {
        let previous_header_metadata = lower_layer_data_buffer.extract_header_metadata();

        // No additional length check is required as `ipv6_parse_extensions` does check all lengths

        let mut extension_array = [Ipv6ExtensionMetadata::default(); MAX_EXTENSIONS];
        let (all_extensions_length, extensions_amount, has_fragment) = ipv6_parse_extensions(
            lower_layer_data_buffer.payload(),
            first_extension as u8,
            &mut extension_array,
        )?;

        Ok((
            DataBuffer {
                header_metadata: Ipv6Extensions {
                    header_start_offset: header_start_offset_from_phi(previous_header_metadata),
                    header_length: all_extensions_length,
                    previous_header_metadata: *previous_header_metadata,
                    extensions: extension_array,
                    extensions_amount,
                },
                buffer: lower_layer_data_buffer.buffer_into_inner(),
            },
            has_fragment,
        ))
    }
}

#[inline]
pub(crate) fn ipv6_parse_extensions<const MAX_EXTENSIONS: usize>(
    buf: &[u8],
    mut next_header_byte: u8,
    extensions: &mut [Ipv6ExtensionMetadata; MAX_EXTENSIONS],
) -> Result<(usize, usize, bool), ParseIpv6ExtensionsError> {
    if MAX_EXTENSIONS == 0 {
        return Err(ParseIpv6ExtensionsError::ExtensionLimitReached);
    }

    let mut extensions_amount = 0;
    let mut all_extensions_length_in_bytes = 0;
    let mut has_fragment = false;

    // 0 Hop by Hop https://www.rfc-editor.org/rfc/rfc8200.html
    // May only appear as first extension
    if next_header_byte == constants::HOP_BY_HOP_EXT {
        // check whether extension's first byte is in range
        if buf.len() < all_extensions_length_in_bytes + EXTENSION_MIN_LEN {
            return Err(ParseIpv6ExtensionsError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: all_extensions_length_in_bytes + EXTENSION_MIN_LEN,
                    actual_length: buf.len(),
                },
            ));
        }

        let next_header_and_length = u16::from_be_bytes(
            buf[all_extensions_length_in_bytes..all_extensions_length_in_bytes + 2]
                .try_into()
                .unwrap(),
        );
        next_header_byte = (next_header_and_length >> 8) as u8;
        let current_extension_length_in_bytes = (usize::from(next_header_and_length as u8) + 1) * 8;

        // check whether whole extension is in range
        if buf.len() < all_extensions_length_in_bytes + current_extension_length_in_bytes {
            return Err(ParseIpv6ExtensionsError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: all_extensions_length_in_bytes
                        + current_extension_length_in_bytes,
                    actual_length: buf.len(),
                },
            ));
        }

        extensions[extensions_amount] = Ipv6ExtensionMetadata::new_typed_ext_type(
            all_extensions_length_in_bytes,
            Ipv6ExtensionType::HopByHop,
        );
        extensions_amount += 1;
        all_extensions_length_in_bytes += current_extension_length_in_bytes;
    }

    #[allow(clippy::mut_range_bound)]
    for _ in extensions_amount..MAX_EXTENSIONS {
        match next_header_byte {
            constants::HOP_BY_HOP_EXT => {
                return Err(ParseIpv6ExtensionsError::InvalidHopByHopPosition)
            }
            // Headers with |Option Type|Hdr Ext Len|... format.
            // Hdr Ext Len is the Length of the Options header in 8-octet units not including the
            // first 8 octets.
            // 43 Routing https://www.rfc-editor.org/rfc/rfc8200.html
            // 60 Destination Options https://www.rfc-editor.org/rfc/rfc8200.html
            constants::ROUTING_EXT => {
                // check whether extension's first byte is in range
                if buf.len() < all_extensions_length_in_bytes + EXTENSION_MIN_LEN {
                    return Err(ParseIpv6ExtensionsError::UnexpectedBufferEnd(
                        UnexpectedBufferEndError {
                            expected_length: all_extensions_length_in_bytes + EXTENSION_MIN_LEN,
                            actual_length: buf.len(),
                        },
                    ));
                }

                let next_header_and_length = u16::from_be_bytes(
                    buf[all_extensions_length_in_bytes..all_extensions_length_in_bytes + 2]
                        .try_into()
                        .unwrap(),
                );
                next_header_byte = (next_header_and_length >> 8) as u8;
                let current_extension_length_in_bytes =
                    (usize::from(next_header_and_length as u8) + 1) * 8;

                // check whether whole extension is in range
                if buf.len() < all_extensions_length_in_bytes + current_extension_length_in_bytes {
                    return Err(ParseIpv6ExtensionsError::UnexpectedBufferEnd(
                        UnexpectedBufferEndError {
                            expected_length: all_extensions_length_in_bytes
                                + current_extension_length_in_bytes,
                            actual_length: buf.len(),
                        },
                    ));
                }

                extensions[extensions_amount] = Ipv6ExtensionMetadata::new_typed_ext_type(
                    all_extensions_length_in_bytes,
                    Ipv6ExtensionType::Routing,
                );

                extensions_amount += 1;
                all_extensions_length_in_bytes += current_extension_length_in_bytes;
            }

            constants::DESTINATION_OPTIONS_EXT => {
                // check whether extension's first byte is in range
                if buf.len() < all_extensions_length_in_bytes + EXTENSION_MIN_LEN {
                    return Err(ParseIpv6ExtensionsError::UnexpectedBufferEnd(
                        UnexpectedBufferEndError {
                            expected_length: all_extensions_length_in_bytes + EXTENSION_MIN_LEN,
                            actual_length: buf.len(),
                        },
                    ));
                }

                let next_header_and_length = u16::from_be_bytes(
                    buf[all_extensions_length_in_bytes..all_extensions_length_in_bytes + 2]
                        .try_into()
                        .unwrap(),
                );
                next_header_byte = (next_header_and_length >> 8) as u8;
                let current_extension_length_in_bytes =
                    (usize::from(next_header_and_length as u8) + 1) * 8;

                // check whether whole extension is in range
                if buf.len() < all_extensions_length_in_bytes + current_extension_length_in_bytes {
                    return Err(ParseIpv6ExtensionsError::UnexpectedBufferEnd(
                        UnexpectedBufferEndError {
                            expected_length: all_extensions_length_in_bytes
                                + current_extension_length_in_bytes,
                            actual_length: buf.len(),
                        },
                    ));
                }

                extensions[extensions_amount] = Ipv6ExtensionMetadata::new_typed_ext_type(
                    all_extensions_length_in_bytes,
                    Ipv6ExtensionType::DestinationOptions,
                );
                extensions_amount += 1;
                all_extensions_length_in_bytes += current_extension_length_in_bytes;
            }
            // Fragment header https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5
            constants::FRAGMENT_EXT => {
                // check whether fragment header is in range
                if buf.len() < all_extensions_length_in_bytes + EXTENSION_MIN_LEN {
                    return Err(ParseIpv6ExtensionsError::UnexpectedBufferEnd(
                        UnexpectedBufferEndError {
                            expected_length: all_extensions_length_in_bytes + EXTENSION_MIN_LEN,
                            actual_length: buf.len(),
                        },
                    ));
                }

                let next_header_reserved_frag_offset_flags = u32::from_be_bytes(
                    buf[all_extensions_length_in_bytes..all_extensions_length_in_bytes + 4]
                        .try_into()
                        .unwrap(),
                );
                let fragment_offset_and_flags = next_header_reserved_frag_offset_flags as u16;
                next_header_byte = (next_header_reserved_frag_offset_flags >> 24) as u8;

                // An atomic fragment is a fragment extension that does not actually indicate any
                // fragmentation. The RFC does allow atomic fragment extensions. It is indicated
                // by an offset of zero and the more fragments flag unset.
                let is_atomic_fragment = 0 == fragment_offset_and_flags & 0b1111_1111_1111_1001;

                extensions[extensions_amount] = Ipv6ExtensionMetadata::new_typed_ext_type(
                    all_extensions_length_in_bytes,
                    Ipv6ExtensionType::Fragment,
                );
                extensions_amount += 1;
                all_extensions_length_in_bytes += EXTENSION_MIN_LEN;

                has_fragment = has_fragment || !is_atomic_fragment;
            }
            _ => {
                // Next header is no extension or an experimental extension, stop the loop.
                break;
            }
        }
    }

    match next_header_byte {
        constants::HOP_BY_HOP_EXT
        | constants::ROUTING_EXT
        | constants::DESTINATION_OPTIONS_EXT
        | constants::FRAGMENT_EXT => Err(ParseIpv6ExtensionsError::ExtensionLimitReached),
        _ => Ok((
            all_extensions_length_in_bytes,
            extensions_amount,
            has_fragment,
        )),
    }
}

impl<PHM, const MAX_EXTENSIONS: usize> HeaderMetadata for Ipv6Extensions<PHM, MAX_EXTENSIONS>
where
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn headroom_internal(&self) -> usize {
        self.previous_header_metadata.headroom_internal()
    }

    #[inline]
    fn header_start_offset(&self, layer: Layer) -> usize {
        if layer == LAYER {
            self.header_start_offset
        } else {
            self.previous_header_metadata.header_start_offset(layer)
        }
    }

    #[inline]
    fn header_length(&self, layer: Layer) -> usize {
        if layer == LAYER {
            self.header_length
        } else {
            self.previous_header_metadata.header_length(layer)
        }
    }

    #[inline]
    fn layer(&self) -> Layer {
        LAYER
    }

    #[inline]
    fn data_length_internal(&self) -> usize {
        self.previous_header_metadata.data_length_internal()
    }
}

impl<PHM, const MAX_EXTENSIONS: usize> HeaderMetadataMut for Ipv6Extensions<PHM, MAX_EXTENSIONS>
where
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn headroom_internal_mut(&mut self) -> &mut usize {
        self.previous_header_metadata.headroom_internal_mut()
    }

    #[inline]
    fn increase_header_start_offset(&mut self, increase_by: usize, layer: Layer) {
        if layer != LAYER {
            self.header_start_offset += increase_by;
            self.previous_header_metadata
                .increase_header_start_offset(increase_by, layer);
        }
    }

    #[inline]
    fn decrease_header_start_offset(&mut self, decrease_by: usize, layer: Layer) {
        if layer != LAYER {
            self.header_start_offset -= decrease_by;
            self.previous_header_metadata
                .decrease_header_start_offset(decrease_by, layer);
        }
    }

    #[inline]
    fn header_length_mut(&mut self, layer: Layer) -> &mut usize {
        if layer == LAYER {
            &mut self.header_length
        } else {
            self.previous_header_metadata.header_length_mut(layer)
        }
    }

    #[inline]
    fn set_data_length(
        &mut self,
        data_length: usize,
        buffer_length: usize,
    ) -> Result<(), LengthExceedsAvailableSpaceError> {
        self.previous_header_metadata
            .set_data_length(data_length, buffer_length)
    }
}

impl<B, PHM, const MAX_EXTENSIONS: usize> Payload
    for DataBuffer<B, Ipv6Extensions<PHM, MAX_EXTENSIONS>>
where
    B: AsRef<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut,
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

impl<B, PHM, const MAX_EXTENSIONS: usize> PayloadMut
    for DataBuffer<B, Ipv6Extensions<PHM, MAX_EXTENSIONS>>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn payload_mut(&mut self) -> &mut [u8] {
        let payload_start = self.header_length(LAYER);
        &mut self.data_buffer_starting_at_header_mut(LAYER)[payload_start..]
    }
}

impl<PHM, const MAX_EXTENSIONS: usize> Ipv6ExtMetaData<MAX_EXTENSIONS>
    for Ipv6Extensions<PHM, MAX_EXTENSIONS>
where
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn extensions_array(&self) -> &[Ipv6ExtensionMetadata; MAX_EXTENSIONS] {
        &self.extensions
    }

    #[inline]
    fn extension(
        &self,
        idx: usize,
    ) -> Result<Ipv6ExtensionMetadata, Ipv6ExtensionIndexOutOfBoundsError> {
        if self.extensions_amount <= idx {
            Err(Ipv6ExtensionIndexOutOfBoundsError {
                used_index: idx,
                extension_amount: self.extensions_amount,
            })
        } else {
            Ok(self.extensions[idx])
        }
    }

    #[inline]
    fn extensions_amount(&self) -> usize {
        self.extensions_amount
    }
}

impl<PHM, const MAX_EXTENSIONS: usize> Ipv6ExtMetaDataMut<MAX_EXTENSIONS>
    for Ipv6Extensions<PHM, MAX_EXTENSIONS>
where
    PHM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn extensions_array_mut(&mut self) -> &mut [Ipv6ExtensionMetadata; MAX_EXTENSIONS] {
        &mut self.extensions
    }
}

impl<B, HM, const MAX_EXTENSIONS: usize> Ipv6ExtMethods<MAX_EXTENSIONS> for DataBuffer<B, HM>
where
    B: AsRef<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + Ipv6ExtMarker<MAX_EXTENSIONS>,
{
}

impl<B, HM, const MAX_EXTENSIONS: usize> Ipv6ExtMethodsMut<MAX_EXTENSIONS> for DataBuffer<B, HM>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + Ipv6ExtMarker<MAX_EXTENSIONS>,
    DataBuffer<B, HM>: UpdateIpv6Length,
{
}

impl<B, HM, const MAX_EXTENSIONS: usize> Ipv6ExtMetaData<MAX_EXTENSIONS> for DataBuffer<B, HM>
where
    B: AsRef<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + Ipv6ExtMarker<MAX_EXTENSIONS>,
{
    #[inline]
    fn extensions_array(&self) -> &[Ipv6ExtensionMetadata; MAX_EXTENSIONS] {
        self.header_metadata.extensions_array()
    }

    #[inline]
    fn extension(
        &self,
        idx: usize,
    ) -> Result<Ipv6ExtensionMetadata, Ipv6ExtensionIndexOutOfBoundsError> {
        self.header_metadata.extension(idx)
    }

    #[inline]
    fn extensions_amount(&self) -> usize {
        self.header_metadata.extensions_amount()
    }
}

impl<B, HM, const MAX_EXTENSIONS: usize> Ipv6ExtMetaDataMut<MAX_EXTENSIONS> for DataBuffer<B, HM>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + Ipv6ExtMarker<MAX_EXTENSIONS>,
{
    #[inline]
    fn extensions_array_mut(&mut self) -> &mut [Ipv6ExtensionMetadata; MAX_EXTENSIONS] {
        self.header_metadata.extensions_array_mut()
    }
}

#[cfg(test)]
mod tests {
    use crate::data_buffer::{BufferIntoInner, DataBuffer, Payload, PayloadMut};
    use crate::error::UnexpectedBufferEndError;
    use crate::ipv6::{Ipv6, Ipv6Methods, Ipv6MethodsMut};
    use crate::ipv6_extensions::error::ParseIpv6ExtensionsError;
    use crate::ipv6_extensions::metadata_trait::Ipv6ExtMetaData;
    use crate::ipv6_extensions::{
        Ipv6ExtFieldError, Ipv6ExtMethods, Ipv6ExtMethodsMut, Ipv6ExtSetFieldError,
        Ipv6ExtTypedHeaderError, Ipv6ExtensionIndexOutOfBoundsError, Ipv6ExtensionMetadata,
        Ipv6ExtensionType, Ipv6Extensions,
    };
    use crate::no_previous_header::NoPreviousHeader;
    use crate::test_utils::copy_into_slice;
    use crate::typed_protocol_headers::InternetProtocolNumber;
    use crate::typed_protocol_headers::RoutingType;

    static IPV6_EXTENSIONS: [u8; 79] = [
        // Version, traffic class and flow label
        0x61,
        0x23,
        0xFF,
        0xFF,
        // Payload Length
        0x00,
        0x27,
        // Next header
        Ipv6ExtensionType::HopByHop as u8,
        // Hop limit
        0xFF,
        // Source
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        // Destination
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xDD,
        // Payload
        Ipv6ExtensionType::Routing as u8,
        0, // Length
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        Ipv6ExtensionType::DestinationOptions as u8,
        0,                              // Length
        RoutingType::SourceRoute as u8, // Routing type
        5,                              // Segments left
        0xBB,                           // Data
        0xBB,                           // Data
        0xBB,                           // Data
        0xBB,                           // Data
        Ipv6ExtensionType::Fragment as u8,
        0, // Length
        0xCC,
        0xCC,
        0xCC,
        0xCC,
        0xCC,
        0xCC,
        InternetProtocolNumber::Tcp as u8,
        0,    // reserved
        0xAB, // Fragment offset
        0xF1, // Fragment offset, reserved, more fragments
        0xFF, // Identification
        0xFF, // Identification
        0xFF, // Identification
        0xFF, // Identification
        0xFF, // Payload start
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
    ];

    static IPV6_NO_FRAGMENT: [u8; 71] = [
        // Version, traffic class and flow label
        0x61,
        0x23,
        0xFF,
        0xFF,
        // Payload Length
        0x00,
        0x1F,
        // Next header
        Ipv6ExtensionType::HopByHop as u8,
        // Hop limit
        0xFF,
        // Source
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        // Destination
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xDD,
        // Payload
        Ipv6ExtensionType::Routing as u8,
        0, // Length
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        Ipv6ExtensionType::DestinationOptions as u8,
        0,                              // Length
        RoutingType::SourceRoute as u8, // Routing type
        5,                              // Segments left
        0xBB,                           // Data
        0xBB,                           // Data
        0xBB,                           // Data
        0xBB,                           // Data
        InternetProtocolNumber::Tcp as u8,
        0, // Length
        0xCC,
        0xCC,
        0xCC,
        0xCC,
        0xCC,
        0xCC,
        0xFF, // Payload start
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
    ];

    static IPV6_EXT_NO_HOP: [u8; 71] = [
        // Version, traffic class and flow label
        0x61,
        0x23,
        0xFF,
        0xFF,
        // Payload Length
        0x00,
        0x1F,
        // Next header
        Ipv6ExtensionType::Routing as u8,
        // Hop limit
        0xFF,
        // Source
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        // Destination
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        // Payload
        Ipv6ExtensionType::DestinationOptions as u8,
        0,                              // Length
        RoutingType::SourceRoute as u8, // Routing type
        5,                              // Segments left
        0xFF,                           // Data
        0xFF,                           // Data
        0xFF,                           // Data
        0xFF,                           // Data
        Ipv6ExtensionType::Fragment as u8,
        0, // Length
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        InternetProtocolNumber::Tcp as u8,
        0,    // reserved
        0xAB, // Fragment offset
        0xF1, // Fragment offset, reserved, more fragments
        0xFF, // Identification
        0xFF, // Identification
        0xFF, // Identification
        0xFF, // Identification
        0xFF, // Payload start
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
    ];

    static IPV6_EXT_ATOMIC_AND_REGULAR_FRAGMENT: [u8; 79] = [
        // Version, traffic class and flow label
        0x61,
        0x23,
        0xFF,
        0xFF,
        // Payload Length
        0x00,
        0x27,
        // Next header
        Ipv6ExtensionType::Fragment as u8,
        // Hop limit
        0xFF,
        // Source
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        // Destination
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xDD,
        // Payload
        Ipv6ExtensionType::Fragment as u8,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        Ipv6ExtensionType::Fragment as u8,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        Ipv6ExtensionType::Fragment as u8,
        0, // Length
        0xCC,
        0xCC,
        0xCC,
        0xCC,
        0xCC,
        0xCC,
        InternetProtocolNumber::Tcp as u8,
        0,    // reserved
        0xAB, // Fragment offset
        0xF1, // Fragment offset, reserved, more fragments
        0xFF, // Identification
        0xFF, // Identification
        0xFF, // Identification
        0xFF, // Identification
        0xFF, // Payload start
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
    ];

    static IPV6_EXT_ONLY_ATOMIC_FRAGMENT: [u8; 64] = [
        // Version, traffic class and flow label
        0x61,
        0x23,
        0xFF,
        0xFF,
        // Payload Length
        0x00,
        0x18,
        // Next header
        Ipv6ExtensionType::Fragment as u8,
        // Hop limit
        0xFF,
        // Source
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        // Destination
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xDD,
        // Payload
        Ipv6ExtensionType::Fragment as u8,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        InternetProtocolNumber::Tcp as u8,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        0x0,
        0xFF, // Payload start
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
    ];

    #[test]
    fn new() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let _ = DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 10>>::parse_ipv6_extensions_layer(
            ipv6,
            next_header,
        )
            .unwrap();

        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXT_NO_HOP, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let _ = DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 10>>::parse_ipv6_extensions_layer(
            ipv6,
            next_header,
        )
            .unwrap();

        let _ = DataBuffer::<_, Ipv6Extensions<NoPreviousHeader, 10>>::parse_ipv6_extensions_alone(
            &IPV6_EXTENSIONS[40..],
            0,
            Ipv6ExtensionType::HopByHop,
        )
        .unwrap();
    }

    #[test]
    fn new_data_buffer_too_short() {
        let mut data = IPV6_EXTENSIONS;
        data[5] = 7;
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(&data[..47], 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        assert_eq!(
            Err(ParseIpv6ExtensionsError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 8,
                    actual_length: 7
                }
            )),
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 10>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
        );

        assert_eq!(
            Err(ParseIpv6ExtensionsError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 8,
                    actual_length: 7,
                }
            )),
            DataBuffer::<_, Ipv6Extensions<NoPreviousHeader, 10>>::parse_ipv6_extensions_alone(
                &IPV6_EXTENSIONS[40..47],
                0,
                Ipv6ExtensionType::HopByHop
            )
        );
    }

    #[test]
    fn new_fragment() {
        let (_exts, has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 10>>::parse_ipv6_extensions_layer(
                DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(&IPV6_EXTENSIONS, 0).unwrap(),
                Ipv6ExtensionType::HopByHop,
            )
                .unwrap();

        assert!(has_fragment);

        let (_exts, has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 10>>::parse_ipv6_extensions_layer(
                DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(&IPV6_NO_FRAGMENT, 0).unwrap(),
                Ipv6ExtensionType::HopByHop,
            )
                .unwrap();

        assert!(!has_fragment);
    }

    #[test]
    fn new_headroom_out_of_range() {
        assert_eq!(
            Err(ParseIpv6ExtensionsError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 290,
                    actual_length: 39,
                }
            )),
            DataBuffer::<_, Ipv6Extensions<NoPreviousHeader, 10>>::parse_ipv6_extensions_alone(
                &IPV6_EXTENSIONS[40..],
                290,
                Ipv6ExtensionType::HopByHop
            )
        );
    }

    #[test]
    fn new_extension_limit_reached() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();
        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        assert_eq!(
            Err(ParseIpv6ExtensionsError::ExtensionLimitReached),
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 0>>::parse_ipv6_extensions_layer(
                ipv6.clone(),
                next_header,
            )
        );
        assert_eq!(
            Err(ParseIpv6ExtensionsError::ExtensionLimitReached),
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 1>>::parse_ipv6_extensions_layer(
                ipv6.clone(),
                next_header,
            )
        );
        assert_eq!(
            Err(ParseIpv6ExtensionsError::ExtensionLimitReached),
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 2>>::parse_ipv6_extensions_layer(
                ipv6.clone(),
                next_header,
            )
        );
        assert_eq!(
            Err(ParseIpv6ExtensionsError::ExtensionLimitReached),
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 3>>::parse_ipv6_extensions_layer(
                ipv6.clone(),
                next_header,
            )
        );
        let _ = DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 4>>::parse_ipv6_extensions_layer(
            ipv6.clone(),
            next_header,
        )
            .unwrap();
    }

    #[test]
    fn new_extension_length_to_large() {
        let mut data = IPV6_EXTENSIONS;
        data[41] = 10;
        let ipv6 = DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(data, 0).unwrap();
        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        assert_eq!(
            Err(ParseIpv6ExtensionsError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 88,
                    actual_length: 39,
                }
            )),
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 10>>::parse_ipv6_extensions_layer(
                ipv6.clone(),
                next_header,
            )
        );

        let mut data = IPV6_EXTENSIONS;
        data[49] = 10;
        let ipv6 = DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(data, 0).unwrap();
        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        assert_eq!(
            Err(ParseIpv6ExtensionsError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 96,
                    actual_length: 39,
                }
            )),
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 10>>::parse_ipv6_extensions_layer(
                ipv6.clone(),
                next_header,
            )
        );
        let mut data = IPV6_EXTENSIONS;
        data[57] = 10;
        let ipv6 = DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(data, 0).unwrap();
        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        assert_eq!(
            Err(ParseIpv6ExtensionsError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 104,
                    actual_length: 39,
                }
            )),
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 10>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
        );
    }

    #[test]
    fn new_extension_too_short() {
        let mut ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();
        ipv6.payload_mut()[1] = 1;
        ipv6.set_ipv6_payload_length(9).unwrap();
        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        assert_eq!(
            Err(ParseIpv6ExtensionsError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 16,
                    actual_length: 9,
                }
            )),
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 10>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
        );

        let mut ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();
        ipv6.set_ipv6_payload_length(15).unwrap();
        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        assert_eq!(
            Err(ParseIpv6ExtensionsError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 16,
                    actual_length: 15,
                }
            )),
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 10>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
        );

        let mut ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();
        ipv6.set_ipv6_payload_length(30).unwrap();
        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        assert_eq!(
            Err(ParseIpv6ExtensionsError::UnexpectedBufferEnd(
                UnexpectedBufferEndError {
                    expected_length: 32,
                    actual_length: 30,
                }
            )),
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 10>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
        );
    }

    #[test]
    fn new_hop_by_hop_not_first() {
        let mut data = IPV6_EXT_NO_HOP;
        data[40] = Ipv6ExtensionType::HopByHop as u8;
        let ipv6 = DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(data, 0).unwrap();

        assert_eq!(
            Err(ParseIpv6ExtensionsError::InvalidHopByHopPosition),
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 10>>::parse_ipv6_extensions_layer(
                ipv6,
                Ipv6ExtensionType::Routing,
            )
        );
    }

    #[test]
    fn new_atomic_and_regular_fragment() {
        let ipv6 = DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(
            IPV6_EXT_ATOMIC_AND_REGULAR_FRAGMENT,
            0,
        )
        .unwrap();
        let (ipv6_ext, is_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 10>>::parse_ipv6_extensions_layer(
                ipv6,
                Ipv6ExtensionType::Fragment,
            )
                .unwrap();
        assert!(is_fragment);
        assert_eq!(
            Ok(Ipv6ExtensionMetadata {
                offset: 0,
                ext_type: Ipv6ExtensionType::Fragment
            }),
            ipv6_ext.extension(0)
        );
        assert_eq!(
            Ok(Ipv6ExtensionMetadata {
                offset: 8,
                ext_type: Ipv6ExtensionType::Fragment
            }),
            ipv6_ext.extension(1)
        );
        assert_eq!(
            Ok(Ipv6ExtensionMetadata {
                offset: 16,
                ext_type: Ipv6ExtensionType::Fragment
            }),
            ipv6_ext.extension(2)
        );
        assert_eq!(
            Ok(Ipv6ExtensionMetadata {
                offset: 24,
                ext_type: Ipv6ExtensionType::Fragment
            }),
            ipv6_ext.extension(3)
        );
    }

    #[test]
    fn new_only_atomic_fragment() {
        let ipv6 = DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(
            IPV6_EXT_ONLY_ATOMIC_FRAGMENT,
            0,
        )
        .unwrap();
        let (ipv6_ext, is_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 10>>::parse_ipv6_extensions_layer(
                ipv6,
                Ipv6ExtensionType::Fragment,
            )
                .unwrap();
        assert!(!is_fragment);
        assert_eq!(
            Ok(Ipv6ExtensionMetadata {
                offset: 0,
                ext_type: Ipv6ExtensionType::Fragment
            }),
            ipv6_ext.extension(0)
        );
        assert_eq!(
            Ok(Ipv6ExtensionMetadata {
                offset: 8,
                ext_type: Ipv6ExtensionType::Fragment
            }),
            ipv6_ext.extension(1)
        );
    }

    #[test]
    fn ipv6_ext_amount() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();
        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 10>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();
        assert_eq!(4, exts.ipv6_ext_amount());
    }

    #[test]
    fn ipv6_extensions() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();
        assert_eq!(
            [
                Some(Ipv6ExtensionType::HopByHop),
                Some(Ipv6ExtensionType::Routing),
                Some(Ipv6ExtensionType::DestinationOptions),
                Some(Ipv6ExtensionType::Fragment),
                None,
            ],
            exts.ipv6_extensions()
        );
    }

    #[test]
    fn ipv6_ext_next_header() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(
            Ok(InternetProtocolNumber::Tcp as u8),
            exts.ipv6_ext_next_header()
        );
    }

    #[test]
    fn ipv6_ext_typed_next_header() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(
            Ok(InternetProtocolNumber::Tcp),
            exts.ipv6_ext_typed_next_header()
        );
    }

    #[test]
    fn ipv6_ext_per_extension_next_header() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(
            Ok(Ipv6ExtensionType::Routing as u8),
            exts.ipv6_ext_per_extension_next_header(0)
        );
        assert_eq!(
            Ok(InternetProtocolNumber::Tcp as u8),
            exts.ipv6_ext_per_extension_next_header(3)
        );

        assert_eq!(
            Err(Ipv6ExtensionIndexOutOfBoundsError {
                used_index: 4,
                extension_amount: 4
            }),
            exts.ipv6_ext_per_extension_next_header(4)
        );
    }

    #[test]
    fn ipv6_ext_per_extension_typed_next_header() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(
            Ok(InternetProtocolNumber::Ipv6Routing),
            exts.ipv6_ext_per_extension_typed_next_header(0)
        );
        assert_eq!(
            Ok(InternetProtocolNumber::Tcp),
            exts.ipv6_ext_per_extension_typed_next_header(3)
        );

        assert_eq!(
            Err(Ipv6ExtTypedHeaderError::Ipv6ExtensionIndexOutOfBounds(
                Ipv6ExtensionIndexOutOfBoundsError {
                    used_index: 4,
                    extension_amount: 4
                }
            )),
            exts.ipv6_ext_per_extension_typed_next_header(4)
        );
    }

    #[test]
    fn ipv6_ext_length() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(Ok(0), exts.ipv6_ext_length(0));
        assert_eq!(Ok(0), exts.ipv6_ext_length(1));
        assert_eq!(Ok(0), exts.ipv6_ext_length(2));
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_length(3)
        );

        assert_eq!(
            Err(Ipv6ExtensionIndexOutOfBoundsError {
                used_index: 4,
                extension_amount: 4
            }),
            exts.ipv6_ext_per_extension_next_header(4)
        );
    }

    #[test]
    fn ipv6_ext_length_in_bytes() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(Ok(8), exts.ipv6_ext_length_in_bytes(0));
        assert_eq!(Ok(8), exts.ipv6_ext_length_in_bytes(1));
        assert_eq!(Ok(8), exts.ipv6_ext_length_in_bytes(2));
        assert_eq!(Ok(8), exts.ipv6_ext_length_in_bytes(3));

        assert_eq!(
            Err(Ipv6ExtensionIndexOutOfBoundsError {
                used_index: 4,
                extension_amount: 4
            }),
            exts.ipv6_ext_length_in_bytes(4)
        );
    }

    #[test]
    fn ipv6_ext_data() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(Ok([0xAA; 6].as_slice()), exts.ipv6_ext_data(0));
        assert_eq!(Ok([0xBB; 4].as_slice()), exts.ipv6_ext_data(1));
        assert_eq!(Ok([0xCC; 6].as_slice()), exts.ipv6_ext_data(2));
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_data(3)
        );

        assert_eq!(
            Err(Ipv6ExtFieldError::Ipv6ExtensionIndexOutOfBounds(
                Ipv6ExtensionIndexOutOfBoundsError {
                    used_index: 4,
                    extension_amount: 4
                }
            )),
            exts.ipv6_ext_data(4)
        );
    }

    #[test]
    fn ipv6_ext_routing_type() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_routing_type(0)
        );
        assert_eq!(
            Ok(RoutingType::SourceRoute as u8),
            exts.ipv6_ext_routing_type(1)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_routing_type(2)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_routing_type(3)
        );

        assert_eq!(
            Err(Ipv6ExtFieldError::Ipv6ExtensionIndexOutOfBounds(
                Ipv6ExtensionIndexOutOfBoundsError {
                    used_index: 4,
                    extension_amount: 4
                }
            )),
            exts.ipv6_ext_routing_type(4)
        );
    }

    #[test]
    fn ipv6_ext_segments_left() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_segments_left(0)
        );
        assert_eq!(Ok(5), exts.ipv6_ext_segments_left(1));
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_segments_left(2)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_segments_left(3)
        );

        assert_eq!(
            Err(Ipv6ExtFieldError::Ipv6ExtensionIndexOutOfBounds(
                Ipv6ExtensionIndexOutOfBoundsError {
                    used_index: 4,
                    extension_amount: 4
                }
            )),
            exts.ipv6_ext_segments_left(4)
        );
    }

    #[test]
    fn ipv6_ext_fragment_offset() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_fragment_offset(0)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_fragment_offset(1)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_fragment_offset(2)
        );
        assert_eq!(Ok(0xABF1 >> 3), exts.ipv6_ext_fragment_offset(3));

        assert_eq!(
            Err(Ipv6ExtFieldError::Ipv6ExtensionIndexOutOfBounds(
                Ipv6ExtensionIndexOutOfBoundsError {
                    used_index: 4,
                    extension_amount: 4
                }
            )),
            exts.ipv6_ext_segments_left(4)
        );
    }

    #[test]
    fn ipv6_ext_more_fragments() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_more_fragments(0)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_more_fragments(1)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_more_fragments(2)
        );
        assert_eq!(Ok(true), exts.ipv6_ext_more_fragments(3));

        assert_eq!(
            Err(Ipv6ExtFieldError::Ipv6ExtensionIndexOutOfBounds(
                Ipv6ExtensionIndexOutOfBoundsError {
                    used_index: 4,
                    extension_amount: 4
                }
            )),
            exts.ipv6_ext_more_fragments(4)
        );
    }

    #[test]
    fn ipv6_ext_fragment_identification() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_fragment_identification(0)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_fragment_identification(1)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_fragment_identification(2)
        );
        assert_eq!(Ok(0xFF_FF_FF_FF), exts.ipv6_ext_fragment_identification(3));

        assert_eq!(
            Err(Ipv6ExtFieldError::Ipv6ExtensionIndexOutOfBounds(
                Ipv6ExtensionIndexOutOfBoundsError {
                    used_index: 4,
                    extension_amount: 4
                }
            )),
            exts.ipv6_ext_fragment_identification(4)
        );
    }

    #[test]
    fn payload() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(&[0xFF; 7], exts.payload());
    }

    #[test]
    fn payload_mut() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (mut exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(&[0xFF; 7], exts.payload_mut());
    }

    #[test]
    fn payload_length() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(7, exts.payload_length());
    }

    #[test]
    fn set_ipv6_ext_next_header() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (mut exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();
        assert_eq!(
            Ok(InternetProtocolNumber::Tcp as u8),
            exts.ipv6_ext_next_header()
        );
        assert_eq!(
            Ok(()),
            exts.set_ipv6_ext_next_header(InternetProtocolNumber::Udp)
        );
        assert_eq!(
            Ok(InternetProtocolNumber::Udp as u8),
            exts.ipv6_ext_next_header()
        );
    }

    #[test]
    fn set_ipv6_ext_length() {
        let mut data = [0; 87];
        copy_into_slice(&mut data, &IPV6_EXTENSIONS, 8);
        let ipv6 = DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(data, 8).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (mut exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(Ok(0), exts.ipv6_ext_length(0));
        assert_eq!(Ok(8), exts.ipv6_ext_length_in_bytes(0));
        assert_eq!(Ok(()), exts.set_ipv6_ext_length(1, 0));
        assert_eq!(Ok(1), exts.ipv6_ext_length(0));
        assert_eq!(Ok(16), exts.ipv6_ext_length_in_bytes(0));
        assert_eq!(
            &[
                Ipv6ExtensionMetadata {
                    offset: 0,
                    ext_type: Ipv6ExtensionType::HopByHop
                },
                Ipv6ExtensionMetadata {
                    offset: 16,
                    ext_type: Ipv6ExtensionType::Routing
                },
                Ipv6ExtensionMetadata {
                    offset: 24,
                    ext_type: Ipv6ExtensionType::DestinationOptions
                },
                Ipv6ExtensionMetadata {
                    offset: 32,
                    ext_type: Ipv6ExtensionType::Fragment
                },
                Ipv6ExtensionMetadata {
                    offset: 0,
                    ext_type: Ipv6ExtensionType::HopByHop
                },
            ],
            exts.extensions_array()
        );

        assert_eq!(
            [
                Ipv6ExtensionType::Routing as u8,
                1, // Length
                0xAA,
                0xAA,
                0xAA,
                0xAA,
                0xAA,
                0xAA,
                Ipv6ExtensionType::Routing as u8,
                0, // Length
                0xAA,
                0xAA,
                0xAA,
                0xAA,
                0xAA,
                0xAA,
                Ipv6ExtensionType::DestinationOptions as u8,
                0,                              // Length
                RoutingType::SourceRoute as u8, // Routing type
                5,                              // Segments left
                0xBB,                           // Data
                0xBB,                           // Data
                0xBB,                           // Data
                0xBB,                           // Data
                Ipv6ExtensionType::Fragment as u8,
                0, // Length
                0xCC,
                0xCC,
                0xCC,
                0xCC,
                0xCC,
                0xCC,
                InternetProtocolNumber::Tcp as u8,
                0,    // reserved
                0xAB, // Fragment offset
                0xF1, // Fragment offset, reserved, more fragments
                0xFF, // Identification
                0xFF, // Identification
                0xFF, // Identification
                0xFF, // Identification
                0xFF, // Payload start
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
            ],
            exts.buffer_get_ref()[40..]
        );

        assert_eq!(Ok(()), exts.set_ipv6_ext_length(0, 0));
        assert_eq!(Ok(0), exts.ipv6_ext_length(0));
        assert_eq!(Ok(8), exts.ipv6_ext_length_in_bytes(0));
        assert_eq!(
            &[
                Ipv6ExtensionMetadata {
                    offset: 0,
                    ext_type: Ipv6ExtensionType::HopByHop
                },
                Ipv6ExtensionMetadata {
                    offset: 8,
                    ext_type: Ipv6ExtensionType::Routing
                },
                Ipv6ExtensionMetadata {
                    offset: 16,
                    ext_type: Ipv6ExtensionType::DestinationOptions
                },
                Ipv6ExtensionMetadata {
                    offset: 24,
                    ext_type: Ipv6ExtensionType::Fragment
                },
                Ipv6ExtensionMetadata {
                    offset: 0,
                    ext_type: Ipv6ExtensionType::HopByHop
                },
            ],
            exts.extensions_array()
        );
        assert_eq!(
            [
                0xDD,
                Ipv6ExtensionType::Routing as u8,
                0, // Length
                0xAA,
                0xAA,
                0xAA,
                0xAA,
                0xAA,
                0xAA,
                Ipv6ExtensionType::DestinationOptions as u8,
                0,                              // Length
                RoutingType::SourceRoute as u8, // Routing type
                5,                              // Segments left
                0xBB,                           // Data
                0xBB,                           // Data
                0xBB,                           // Data
                0xBB,                           // Data
                Ipv6ExtensionType::Fragment as u8,
                0, // Length
                0xCC,
                0xCC,
                0xCC,
                0xCC,
                0xCC,
                0xCC,
                InternetProtocolNumber::Tcp as u8,
                0,    // reserved
                0xAB, // Fragment offset
                0xF1, // Fragment offset, reserved, more fragments
                0xFF, // Identification
                0xFF, // Identification
                0xFF, // Identification
                0xFF, // Identification
                0xFF, // Payload start
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
            ],
            exts.buffer_get_ref()[47..]
        );
        assert_eq!(Ok(()), exts.set_ipv6_ext_length(0, 0));
        assert_eq!(Ok(0), exts.ipv6_ext_length(0));
        assert_eq!(Ok(8), exts.ipv6_ext_length_in_bytes(0));

        assert_eq!(
            Err(Ipv6ExtSetFieldError::HeaderFieldDoesNotExist),
            exts.set_ipv6_ext_length(0, 3)
        );
    }

    #[test]
    fn ipv6_ext_data_mut() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (mut exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(Ok([0xAA; 6].as_mut_slice()), exts.ipv6_ext_data_mut(0));
        assert_eq!(Ok([0xBB; 4].as_mut_slice()), exts.ipv6_ext_data_mut(1));
        assert_eq!(Ok([0xCC; 6].as_mut_slice()), exts.ipv6_ext_data_mut(2));
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.ipv6_ext_data_mut(3)
        );

        assert_eq!(
            Err(Ipv6ExtFieldError::Ipv6ExtensionIndexOutOfBounds(
                Ipv6ExtensionIndexOutOfBoundsError {
                    used_index: 4,
                    extension_amount: 4
                }
            )),
            exts.ipv6_ext_data_mut(4)
        );
    }
    #[test]
    fn set_ipv6_ext_routing_type() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (mut exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.set_ipv6_ext_routing_type(RoutingType::Nimrod, 0)
        );
        assert_eq!(
            Ok(RoutingType::SourceRoute as u8),
            exts.ipv6_ext_routing_type(1)
        );
        assert_eq!(
            Ok(()),
            exts.set_ipv6_ext_routing_type(RoutingType::Nimrod, 1)
        );
        assert_eq!(Ok(RoutingType::Nimrod as u8), exts.ipv6_ext_routing_type(1));
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.set_ipv6_ext_routing_type(RoutingType::Nimrod, 2)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.set_ipv6_ext_routing_type(RoutingType::Nimrod, 3)
        );

        assert_eq!(
            Err(Ipv6ExtFieldError::Ipv6ExtensionIndexOutOfBounds(
                Ipv6ExtensionIndexOutOfBoundsError {
                    used_index: 4,
                    extension_amount: 4
                }
            )),
            exts.set_ipv6_ext_routing_type(RoutingType::Nimrod, 4)
        );
    }

    #[test]
    fn set_ipv6_ext_segments_left() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (mut exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.set_ipv6_ext_segments_left(1, 0)
        );
        assert_eq!(Ok(5), exts.ipv6_ext_segments_left(1));
        assert_eq!(Ok(()), exts.set_ipv6_ext_segments_left(1, 1));
        assert_eq!(Ok(1), exts.ipv6_ext_segments_left(1));
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.set_ipv6_ext_segments_left(1, 2)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.set_ipv6_ext_segments_left(1, 3)
        );

        assert_eq!(
            Err(Ipv6ExtFieldError::Ipv6ExtensionIndexOutOfBounds(
                Ipv6ExtensionIndexOutOfBoundsError {
                    used_index: 4,
                    extension_amount: 4
                }
            )),
            exts.set_ipv6_ext_segments_left(1, 4)
        );
    }

    #[test]
    fn set_ipv6_ext_fragment_offset() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (mut exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.set_ipv6_ext_fragment_offset(0xFEDC, 0)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.set_ipv6_ext_fragment_offset(0xFEDC, 1)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.set_ipv6_ext_fragment_offset(0xFEDC, 2)
        );
        assert_eq!(Ok(0xABF1 >> 3), exts.ipv6_ext_fragment_offset(3));
        assert_eq!(Ok(()), exts.set_ipv6_ext_fragment_offset(0xFEDC, 3));
        assert_eq!(Ok(0x1EDC), exts.ipv6_ext_fragment_offset(3));

        assert_eq!(
            Err(Ipv6ExtFieldError::Ipv6ExtensionIndexOutOfBounds(
                Ipv6ExtensionIndexOutOfBoundsError {
                    used_index: 4,
                    extension_amount: 4
                }
            )),
            exts.set_ipv6_ext_fragment_offset(0xFEDC, 4)
        );
    }

    #[test]
    fn set_ipv6_ext_more_fragments() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (mut exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.set_ipv6_ext_more_fragments(false, 0)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.set_ipv6_ext_more_fragments(false, 1)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.set_ipv6_ext_more_fragments(false, 2)
        );
        assert_eq!(Ok(true), exts.ipv6_ext_more_fragments(3));
        assert_eq!(Ok(()), exts.set_ipv6_ext_more_fragments(false, 3));
        assert_eq!(Ok(false), exts.ipv6_ext_more_fragments(3));

        assert_eq!(
            Err(Ipv6ExtFieldError::Ipv6ExtensionIndexOutOfBounds(
                Ipv6ExtensionIndexOutOfBoundsError {
                    used_index: 4,
                    extension_amount: 4
                }
            )),
            exts.set_ipv6_ext_more_fragments(false, 4)
        );
    }

    #[test]
    fn set_ipv6_ext_fragment_identification() {
        let ipv6 =
            DataBuffer::<_, Ipv6<NoPreviousHeader>>::parse_ipv6_alone(IPV6_EXTENSIONS, 0).unwrap();

        let next_header = ipv6.ipv6_next_header().try_into().unwrap();

        let (mut exts, _has_fragment) =
            DataBuffer::<_, Ipv6Extensions<Ipv6<NoPreviousHeader>, 5>>::parse_ipv6_extensions_layer(
                ipv6,
                next_header,
            )
                .unwrap();

        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.set_ipv6_ext_fragment_identification(0xAA_AA_AA_AA, 0)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.set_ipv6_ext_fragment_identification(0xAA_AA_AA_AA, 1)
        );
        assert_eq!(
            Err(Ipv6ExtFieldError::HeaderFieldDoesNotExist),
            exts.set_ipv6_ext_fragment_identification(0xAA_AA_AA_AA, 2)
        );
        assert_eq!(Ok(0xFF_FF_FF_FF), exts.ipv6_ext_fragment_identification(3));
        assert_eq!(
            Ok(()),
            exts.set_ipv6_ext_fragment_identification(0xAA_AA_AA_AA, 3)
        );
        assert_eq!(Ok(0xAA_AA_AA_AA,), exts.ipv6_ext_fragment_identification(3));

        assert_eq!(
            Err(Ipv6ExtFieldError::Ipv6ExtensionIndexOutOfBounds(
                Ipv6ExtensionIndexOutOfBoundsError {
                    used_index: 4,
                    extension_amount: 4
                }
            )),
            exts.set_ipv6_ext_fragment_identification(0xAAAAAAAA, 4)
        );
    }
}
