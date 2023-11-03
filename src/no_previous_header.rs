//! Helper layer to parse non-Ethernet headers without underlying headers.

use crate::data_buffer::traits::{BufferAccess, HeaderInformation, HeaderInformationMut, Layer};
use crate::data_buffer::{DataBuffer, Payload};
use crate::error::UnexpectedBufferEndError;

/// Contains meta data about the headroom and data length.
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash, Copy, Clone, Debug)]
pub struct NoPreviousHeaderInformation {
    headroom: usize,
    data_length: usize,
}

impl NoPreviousHeaderInformation {
    #[inline]
    pub fn new(headroom: usize, buffer_length: usize) -> Self {
        Self {
            headroom,
            data_length: buffer_length - headroom,
        }
    }
}

impl<B> DataBuffer<B, NoPreviousHeaderInformation>
where
    B: AsRef<[u8]>,
{
    /// Parses `buf` and creates a new [DataBuffer].
    ///
    /// `headroom` indicates the amount of headroom in the provided `buf`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the provided data buffer is shorter than expected.
    #[inline]
    pub(crate) fn new(
        buf: B,
        headroom: usize,
    ) -> Result<DataBuffer<B, NoPreviousHeaderInformation>, UnexpectedBufferEndError> {
        if buf.as_ref().len() < headroom {
            return Err(UnexpectedBufferEndError {
                expected_length: headroom,
                actual_length: buf.as_ref().len(),
            });
        }
        Ok(DataBuffer {
            header_information: NoPreviousHeaderInformation::new(headroom, buf.as_ref().len()),
            buffer: buf,
        })
    }
}

impl HeaderInformation for NoPreviousHeaderInformation {
    #[inline]
    fn headroom_internal(&self) -> usize {
        self.headroom
    }

    #[inline]
    fn header_start_offset(&self, _layer: Layer) -> usize {
        0
    }

    #[inline]
    fn header_length(&self, _layer: Layer) -> usize {
        0
    }

    #[inline]
    fn layer(&self) -> Layer {
        Layer::NoPreviousHeader
    }

    #[inline]
    fn data_length(&self) -> usize {
        self.data_length
    }
}

impl HeaderInformationMut for NoPreviousHeaderInformation {
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
        unreachable!("NoPreviousHeader length cannot be changed")
    }

    #[inline]
    fn set_data_length(
        &mut self,
        data_length: usize,
        buffer_length: usize,
    ) -> Result<(), UnexpectedBufferEndError> {
        if data_length + self.headroom > buffer_length {
            Err(UnexpectedBufferEndError {
                expected_length: data_length,
                actual_length: buffer_length - self.headroom,
            })
        } else {
            self.data_length = data_length;
            Ok(())
        }
    }
}

impl<B> Payload for DataBuffer<B, NoPreviousHeaderInformation>
where
    B: AsRef<[u8]>,
{
    #[inline]
    fn payload(&self) -> &[u8] {
        self.data_buffer_starting_at_header(self.layer())
    }

    #[inline]
    fn payload_length(&self) -> usize {
        self.payload().len()
    }
}
