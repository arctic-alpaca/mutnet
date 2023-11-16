//! Wrapper for network data buffer and parsed protocols metadata.
pub(crate) mod traits;

use crate::data_buffer::traits::HeaderMetadataExtraction;
pub(crate) use crate::data_buffer::traits::*;
pub use crate::data_buffer::traits::{BufferIntoInner, Payload, PayloadMut};
use crate::error::LengthExceedsAvailableSpaceError;
use core::ops::Range;

/// Wraps the data buffer and contains metadata about the parsed protocols.
#[allow(private_bounds)]
#[derive(Eq, PartialEq, Hash, Debug)]
pub struct DataBuffer<B, HM>
where
    B: AsRef<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut,
{
    /// Metadata of the already parsed headers.
    pub(crate) header_metadata: HM,
    /// The data buffer.
    pub(crate) buffer: B,
}

impl<B, HM> HeaderMetadataExtraction<HM> for DataBuffer<B, HM>
where
    B: AsRef<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut + Copy,
{
    #[inline]
    fn extract_header_metadata(&self) -> &HM {
        &self.header_metadata
    }
}

impl<B, HM> HeaderMetadataMut for DataBuffer<B, HM>
where
    B: AsRef<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn headroom_internal_mut(&mut self) -> &mut usize {
        self.header_metadata.headroom_internal_mut()
    }

    #[inline]
    fn increase_header_start_offset(&mut self, increase_by: usize, layer: Layer) {
        self.header_metadata
            .increase_header_start_offset(increase_by, layer);
    }

    #[inline]
    fn decrease_header_start_offset(&mut self, decrease_by: usize, layer: Layer) {
        self.header_metadata
            .decrease_header_start_offset(decrease_by, layer);
    }

    #[inline]
    fn header_length_mut(&mut self, layer: Layer) -> &mut usize {
        self.header_metadata.header_length_mut(layer)
    }

    #[inline]
    fn set_data_length(
        &mut self,
        data_length: usize,
        buffer_length: usize,
    ) -> Result<(), LengthExceedsAvailableSpaceError> {
        self.header_metadata
            .set_data_length(data_length, buffer_length)
    }
}

impl<B, HM> HeaderManipulation for DataBuffer<B, HM>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut,
{
}

impl<B, HM> HeaderMetadata for DataBuffer<B, HM>
where
    B: AsRef<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn headroom_internal(&self) -> usize {
        self.header_metadata.headroom_internal()
    }
    #[inline]
    fn header_start_offset(&self, layer: Layer) -> usize {
        self.header_metadata.header_start_offset(layer)
    }
    #[inline]
    fn header_length(&self, layer: Layer) -> usize {
        self.header_metadata.header_length(layer)
    }

    #[inline]
    fn layer(&self) -> Layer {
        self.header_metadata.layer()
    }

    #[inline]
    fn data_length(&self) -> usize {
        self.header_metadata.data_length()
    }
}

impl<B, HM> BufferAccess for DataBuffer<B, HM>
where
    B: AsRef<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn buffer_length(&self) -> usize {
        self.buffer.as_ref().len()
    }

    #[inline]
    fn data_buffer_starting_at_header(&self, layer: Layer) -> &[u8] {
        let range = calculate_range_from_header_offset_to_data_end(self, layer);
        &self.buffer.as_ref()[range]
    }

    #[inline]
    fn read_slice(&self, layer: Layer, range: Range<usize>) -> &[u8] {
        &self.data_buffer_starting_at_header(layer)[range]
    }

    #[inline]
    fn read_value(&self, layer: Layer, idx: usize) -> u8 {
        self.data_buffer_starting_at_header(layer)[idx]
    }

    #[inline]
    fn read_array<const N: usize>(&self, layer: Layer, range: Range<usize>) -> [u8; N] {
        self.data_buffer_starting_at_header(layer)[range]
            .try_into()
            .unwrap()
    }
}

#[inline]
fn calculate_range_from_header_offset_to_data_end<B, HM>(
    data_buffer: &DataBuffer<B, HM>,
    layer: Layer,
) -> Range<usize>
where
    B: AsRef<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut,
{
    let start = data_buffer.header_metadata.headroom_internal()
        + data_buffer.header_metadata.header_start_offset(layer);
    let end =
        data_buffer.header_metadata.headroom_internal() + data_buffer.header_metadata.data_length();
    start..end
}

impl<B, HM> BufferAccessMut for DataBuffer<B, HM>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn data_buffer_starting_at_header_mut(&mut self, layer: Layer) -> &mut [u8] {
        let range = calculate_range_from_header_offset_to_data_end(self, layer);
        &mut self.buffer.as_mut()[range]
    }

    #[inline]
    fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[..]
    }

    #[inline]
    fn get_slice_mut(&mut self, layer: Layer, range: Range<usize>) -> &mut [u8] {
        &mut self.data_buffer_starting_at_header_mut(layer)[range]
    }

    #[inline]
    fn write_value(&mut self, layer: Layer, idx: usize, value: u8) {
        self.data_buffer_starting_at_header_mut(layer)[idx] = value;
    }

    #[inline]
    fn write_slice(&mut self, layer: Layer, range: Range<usize>, slice: &[u8]) {
        self.data_buffer_starting_at_header_mut(layer)[range].copy_from_slice(slice);
    }
}

impl<B, HM> BufferIntoInner<B> for DataBuffer<B, HM>
where
    B: AsRef<[u8]>,
    HM: HeaderMetadata + HeaderMetadataMut,
{
    #[inline]
    fn headroom(&self) -> usize {
        HeaderMetadata::headroom_internal(self)
    }

    #[inline]
    fn buffer_into_inner(self) -> B {
        self.buffer
    }

    #[inline]
    fn buffer_get_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl<B, HM> Clone for DataBuffer<B, HM>
where
    B: AsRef<[u8]> + Clone,
    HM: HeaderMetadata + HeaderMetadataMut + Copy,
{
    #[inline]
    fn clone(&self) -> Self {
        DataBuffer {
            buffer: self.buffer.clone(),
            header_metadata: self.header_metadata,
        }
    }
}
