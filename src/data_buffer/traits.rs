//! Traits used to access header metadata or network data from the [`DataBuffer`].

use crate::error::{LengthExceedsAvailableSpaceError, NotEnoughHeadroomError};
use crate::ipv6_extensions::{Ipv6ExtMetaData, Ipv6ExtMetaDataMut};
use core::ops::Range;

/// Provides access to the underlying data buffer.
pub trait BufferIntoInner<B>
where
    B: AsRef<[u8]>,
{
    /// Returns the amount of headroom the buffer currently has.
    fn headroom(&self) -> usize;

    /// Returns the underlying buffer.
    fn buffer_into_inner(self) -> B;

    /// Returns a reference to the underlying buffer.
    fn buffer_get_ref(&self) -> &[u8];
}

/// Access the highest parsed layer's payload.
pub trait Payload {
    /// Returns a reference to the highest parsed layer's payload.
    fn payload(&self) -> &[u8];
    /// Returns the length of the highest parsed layer's payload.
    fn payload_length(&self) -> usize;
}

/// Access the highest parsed layer's payload.
pub trait PayloadMut {
    /// Returns a mutable reference to the highest parsed layer's payload.
    fn payload_mut(&mut self) -> &mut [u8];
}

/// Allows extracting the header metadata from a `DataBuffer`.
pub(crate) trait HeaderMetadataExtraction<HM>
where
    HM: HeaderMetadata + HeaderMetadataMut + Copy,
{
    /// Returns the stack of parsed protocols metadata structs.
    fn extract_header_metadata(&self) -> &HM;
}

/// Trait marking a layer to implement Ethernet methods.
pub(crate) trait EthernetMarker: HeaderMetadata + HeaderMetadataMut {}
/// Trait marking a layer to implement IEEE 802.1Q methods.
pub(crate) trait Ieee802_1QVlanMarker: HeaderMetadata + HeaderMetadataMut {}
/// Trait marking a layer to implement ARP methods.
pub(crate) trait ArpMarker: HeaderMetadata + HeaderMetadataMut {}
/// Trait marking a layer to implement IPv4 methods.
pub(crate) trait Ipv4Marker: HeaderMetadata + HeaderMetadataMut {}
/// Trait marking a layer to implement IPv6 methods.
pub(crate) trait Ipv6Marker: HeaderMetadata + HeaderMetadataMut {}
/// Trait marking a layer to implement IPv6 extensions methods.
pub(crate) trait Ipv6ExtMarker<const MAX_EXTENSIONS: usize>:
    HeaderMetadata
    + HeaderMetadataMut
    + Ipv6ExtMetaData<MAX_EXTENSIONS>
    + Ipv6ExtMetaDataMut<MAX_EXTENSIONS>
{
}
/// Trait marking a layer to implement TCP methods.
pub(crate) trait TcpMarker: HeaderMetadata + HeaderMetadataMut {}
/// Trait marking a layer to implement UDP methods.
pub(crate) trait UdpMarker: HeaderMetadata + HeaderMetadataMut {}

/// Indicates the layer requesting data.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub(crate) enum Layer {
    NoPreviousHeader,
    EthernetII,
    Ieee802_1QVlan,
    Arp,
    Ipv4,
    Ipv6,
    Ipv6Ext,
    Tcp,
    Udp,
}

/// Methods to access the data buffer.
pub(crate) trait BufferAccess {
    /// Returns the length of the complete data buffer.
    fn buffer_length(&self) -> usize;

    /// Returns a slice containing data starting at `layer` and ending with the data length end.
    ///
    /// Is data length aware. This means it will limit the slice to the length of the data as
    /// indicated by length header fields and not just return all data until the end of the buffer.
    fn data_buffer_starting_at_header(&self, layer: Layer) -> &[u8];

    /// Returns a slice as indicated by `range` starting from `layer`.
    fn read_slice(&self, layer: Layer, range: Range<usize>) -> &[u8];
    /// Returns the byte at `idx` starting from `layer`.
    fn read_value(&self, layer: Layer, idx: usize) -> u8;
    /// Returns an array as indicated by `range` starting from `layer`.
    fn read_array<const N: usize>(&self, layer: Layer, range: Range<usize>) -> [u8; N];
}

/// Methods to mutably access the data buffer.
pub(crate) trait BufferAccessMut {
    /// Returns a mutable slice containing data starting at `layer` and ending with the data length end.
    ///
    /// Is data length aware. This means it will limit the slice to the length of the data as
    /// indicated by length header fields and not just return all data until the end of the buffer.
    fn data_buffer_starting_at_header_mut(&mut self, layer: Layer) -> &mut [u8];

    /// Returns a mutable slice to the whole data buffer.
    fn buffer_mut(&mut self) -> &mut [u8];

    /// Returns a mutable slice as indicated by `range` starting from `layer`.
    fn get_slice_mut(&mut self, layer: Layer, range: Range<usize>) -> &mut [u8];
    /// Writes `value` at `idx` starting from `layer`.
    fn write_value(&mut self, layer: Layer, idx: usize, value: u8);
    /// Writes overwrites `range` with `slice` starting from `layer`.
    ///
    /// # Panics:
    /// Panics if `range` and `slice` are not the same length.
    fn write_slice(&mut self, layer: Layer, range: Range<usize>, slice: &[u8]);
}

/// Methods to access header metadata.
pub(crate) trait HeaderMetadata {
    /// Returns the amount of headroom of the data buffer.
    ///
    /// Buffer:
    /// ```text
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |  Headroom   |                      Data                       |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    fn headroom_internal(&self) -> usize;

    /// Returns the offset of the start of the requested layers header from the start of the
    /// data buffer.
    ///
    /// Buffer:
    /// ```text
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |  Headroom   |  Previous Header Data |     Current Header      |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///               ^---------offset--------^
    /// ```
    fn header_start_offset(&self, layer: Layer) -> usize;

    /// Returns the length of the header (without payload) in bytes.
    fn header_length(&self, layer: Layer) -> usize;

    /// Returns the current layer.
    fn layer(&self) -> Layer;

    /// Returns the data length.
    ///
    /// Data length is the amount of bytes from the first header byte to the end of the payload.
    fn data_length(&self) -> usize;
}

/// Methods to manipulate the header and headroom.
///
/// Growing and shrinking the header and the headroom.
pub(crate) trait HeaderManipulation:
    BufferAccess + BufferAccessMut + HeaderMetadata + HeaderMetadataMut
{
    /// Grows the header, shrinks the headroom.
    ///
    /// Handles data length and manipulation of all header start offsets.
    ///
    /// # Errors
    ///
    /// Returns an error if there is not enough headroom available.
    ///
    /// # Panics
    ///
    /// Panics if `current_header_bytes_to_move` is no larger than the header length of `layer`.
    #[inline]
    fn grow_header(
        &mut self,
        current_header_bytes_to_move: usize,
        grow_by: usize,
        layer: Layer,
    ) -> Result<(), NotEnoughHeadroomError> {
        if self.headroom_internal() >= grow_by {
            assert!(current_header_bytes_to_move <= self.header_length(layer));

            let start = self.headroom_internal();
            let end = self.headroom_internal()
                + self.header_start_offset(layer)
                + current_header_bytes_to_move;
            let destination = self.headroom_internal() - grow_by;
            *self.header_length_mut(layer) += grow_by;
            self.increase_header_start_offset(grow_by, layer);
            *self.headroom_internal_mut() -= grow_by;
            let data_length = self.data_length() + grow_by;
            self.set_data_length(data_length, self.buffer_length())
                .expect("grow_by cannot set the data end higher than the buffer length");
            self.buffer_mut().copy_within(start..end, destination);
            Ok(())
        } else {
            Err(NotEnoughHeadroomError {
                required: grow_by,
                available: self.headroom_internal(),
            })
        }
    }

    /// Shrinks the header, grows the headroom.
    ///
    /// Handles data length and manipulation of all header start offsets.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - the layer's header length is less that `shrink_by`.
    /// - `current_header_bytes_to_move` is no larger than the layer's header length minus `shrink_by`.
    #[inline]
    fn shrink_header(
        &mut self,
        current_header_bytes_to_move: usize,
        shrink_by: usize,
        layer: Layer,
    ) {
        assert!(self.header_length(layer) > shrink_by);
        assert!(current_header_bytes_to_move <= self.header_length(layer) - shrink_by);

        let start = self.headroom_internal();
        let end = self.headroom_internal()
            + self.header_start_offset(layer)
            + current_header_bytes_to_move;
        let destination = self.headroom_internal() + shrink_by;
        *self.header_length_mut(layer) -= shrink_by;
        self.decrease_header_start_offset(shrink_by, layer);
        *self.headroom_internal_mut() += shrink_by;
        let data_length = self.data_length() - shrink_by;
        self.set_data_length(data_length, self.buffer_length())
            .expect("shrink_header cannot set the data end higher than the buffer length");
        self.buffer_mut().copy_within(start..end, destination);
    }
}

pub(crate) trait HeaderMetadataMut {
    /// Returns a mutable reference to the amount of headroom available.
    ///
    /// Data buffer:
    /// ```text
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Headroom  |                      Data                       |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ^-------------^
    /// ```
    fn headroom_internal_mut(&mut self) -> &mut usize;

    /// Increases the header start offset of all layers higher than `layer`.
    fn increase_header_start_offset(&mut self, increase_by: usize, layer: Layer);
    /// Decreases the header start offset of all layers higher than `layer`.
    fn decrease_header_start_offset(&mut self, decrease_by: usize, layer: Layer);

    /// Returns the length of the header (without payload) in bytes.
    fn header_length_mut(&mut self, layer: Layer) -> &mut usize;

    /// Sets the data length.
    ///
    /// # Errors
    ///
    /// Returns an error if `data_length` and headroom combined are larger than the `buffer_length`.
    fn set_data_length(
        &mut self,
        data_length: usize,
        buffer_length: usize,
    ) -> Result<(), LengthExceedsAvailableSpaceError>;
}
