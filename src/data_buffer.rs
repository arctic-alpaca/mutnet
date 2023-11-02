//! [`DataBuffer`] handles the access to the wrapped data.
//! To do so, the marker type used to identify the protocol or nested protocols contains the required
//! metadata like header lengths, headroom size, etc.
//!
//! To allow for as much flexibility as possible, [`DataBuffer`] takes `AsRef<[u8]>` or
//! `AsRef<[u8]> + AsMut<[u8]>`.
//! To use the data-buffers without copying data into them, it is important to provide a reference
//! to the data if the provided buffer implements [`Copy`]:
//! ```no_run
//! # use mutnet::arp::Arp;
//! # use mutnet::data_buffer::DataBuffer;
//! # use std::error::Error;
//! #
//! # fn main() -> Result<(), Box<dyn Error>> {
//! // Arrays is Rust will implement `Copy` if the element type implements element type `Copy`
//! use mutnet::no_previous_header::NoPreviousHeaderInformation;
//! let network_data = [0xFF; 1000];
//! // Copies the data from network_data
//! let data_buffer = DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(network_data, 0)?;
//! // No copy
//! let data_buffer = DataBuffer::<_, Arp<NoPreviousHeaderInformation>>::new(&network_data, 0)?;
//! # Ok(())
//! # }
//! ```
//!
//! The copying of data propagates through the parsing so if you provide a buffer to copy, every
//! time a new protocol layer is parsed, the data will be copied

pub(crate) mod traits;

use crate::data_buffer::traits::HeaderInformationExtraction;
pub(crate) use crate::data_buffer::traits::*;
pub use crate::data_buffer::traits::{BufferIntoInner, Payload, PayloadMut};
use crate::error::UnexpectedBufferEndError;

/// Wraps the underlying buffer containing the network data and optional headroom.
#[derive(Eq, PartialEq, Hash, Debug)]
pub struct DataBuffer<B, H>
where
    B: AsRef<[u8]>,
    H: HeaderInformation + HeaderInformationMut,
{
    pub(crate) header_information: H,
    pub(crate) buffer: B,
}

impl<B, H> HeaderInformationExtraction<H> for DataBuffer<B, H>
where
    B: AsRef<[u8]>,
    H: HeaderInformation + HeaderInformationMut + Copy,
{
    #[inline]
    fn extract_header_information(&self) -> &H {
        &self.header_information
    }
}

impl<B, H> HeaderInformationMut for DataBuffer<B, H>
where
    B: AsRef<[u8]>,
    H: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn headroom_mut(&mut self) -> &mut usize {
        self.header_information.headroom_mut()
    }

    #[inline]
    fn increase_header_start_offset(&mut self, increase_by: usize, layer: Layer) {
        self.header_information
            .increase_header_start_offset(increase_by, layer);
    }

    #[inline]
    fn decrease_header_start_offset(&mut self, decrease_by: usize, layer: Layer) {
        self.header_information
            .decrease_header_start_offset(decrease_by, layer);
    }

    #[inline]
    fn header_length_mut(&mut self, layer: Layer) -> &mut usize {
        self.header_information.header_length_mut(layer)
    }

    #[inline]
    fn set_data_length(
        &mut self,
        data_length: usize,
        buffer_length: usize,
    ) -> Result<(), UnexpectedBufferEndError> {
        self.header_information
            .set_data_length(data_length, buffer_length)
    }
}

impl<B, H> HeaderManipulation for DataBuffer<B, H>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    H: HeaderInformation + HeaderInformationMut,
{
}

impl<B, H> HeaderInformation for DataBuffer<B, H>
where
    B: AsRef<[u8]>,
    H: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn headroom(&self) -> usize {
        self.header_information.headroom()
    }
    #[inline]
    fn header_start_offset(&self, layer: Layer) -> usize {
        self.header_information.header_start_offset(layer)
    }
    #[inline]
    fn header_length(&self, layer: Layer) -> usize {
        self.header_information.header_length(layer)
    }

    #[inline]
    fn layer(&self) -> Layer {
        self.header_information.layer()
    }

    #[inline]
    fn data_length(&self) -> usize {
        self.header_information.data_length()
    }
}

impl<B, H> BufferAccess for DataBuffer<B, H>
where
    B: AsRef<[u8]>,
    H: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn buffer_length(&self) -> usize {
        self.buffer.as_ref().len()
    }

    /// Data length aware
    #[inline]
    fn data_buffer_starting_at_header(&self, layer: Layer) -> &[u8] {
        &self.buffer.as_ref()[calulcate_data_buffer_starting_at_header_start_and_end(self, layer)]
    }
}

#[inline]
fn calulcate_data_buffer_starting_at_header_start_and_end<B, H>(
    data_buffer: &DataBuffer<B, H>,
    layer: Layer,
) -> core::ops::Range<usize>
where
    B: AsRef<[u8]>,
    H: HeaderInformation + HeaderInformationMut,
{
    let start = data_buffer.header_information.headroom()
        + data_buffer.header_information.header_start_offset(layer);
    let end =
        data_buffer.header_information.headroom() + data_buffer.header_information.data_length();
    assert!(start <= end);
    start..end
}

impl<B, H> BufferAccessMut for DataBuffer<B, H>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    H: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn data_buffer_starting_at_header_mut(&mut self, layer: Layer) -> &mut [u8] {
        let range = calulcate_data_buffer_starting_at_header_start_and_end(self, layer);
        &mut self.buffer.as_mut()[range]
    }

    #[inline]
    fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[..]
    }
}

impl<B, H> BufferIntoInner<B> for DataBuffer<B, H>
where
    B: AsRef<[u8]>,
    H: HeaderInformation + HeaderInformationMut,
{
    #[inline]
    fn buffer_into_inner(self) -> B {
        self.buffer
    }

    #[inline]
    fn buffer_get_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl<B, H> Clone for DataBuffer<B, H>
where
    B: AsRef<[u8]> + Clone,
    H: HeaderInformation + HeaderInformationMut + Copy,
{
    #[inline]
    fn clone(&self) -> Self {
        DataBuffer {
            buffer: self.buffer.clone(),
            header_information: self.header_information,
        }
    }
}
