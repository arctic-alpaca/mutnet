# Why not use a struct-per-layer approach?
To manipulate the underlying data buffer, any struct would need to own the data buffer or have a mutable reference to it.
This could be achieved by [splitting](https://doc.rust-lang.org/std/primitive.slice.html#method.split_at_mut) the buffer,
but would lead to multiple structs having mutable references to non-overlapping parts of the data buffer.
With this division, moving parts of the headers would become impossible as it affects all lower layers.
In consequence, a single struct, the `DataBuffer` needs to own the only mutable reference to the entirety of the
underlying data buffer.

# Why use traits for the layers' methods?
It would have been possible to implement all layer's methods for the `DataBuffer` struct directly with appropriate trait bounds.
This would lead to crate users needing to specify the exact trait bound in functions expecting every possible `DataBuffer`
implementing TCP-related methods.
Instead, using traits allows to specify easy to read `impl XYZ` parameters.
The following two functions show the difference (the code is just an illustration and not expected to work anymore).

```rust
// Using trait bounds directly
pub fn no_traits<B, H>(packet: DataBuffer<B, H>, lock: &mut StdoutLock)
where
    B: AsRef<[u8]> + AsMut<[u8]>,
    H: TcpMarker,
    DataBuffer<B, H>: TcpChecksum + UpdateIpLength + PayloadMut,
{
    println!("TCP: dst: {:?}", packet.tcp_destination_port()).unwrap();
    println!("TCP: src: {:?}", packet.tcp_source_port()).unwrap();
    packet.tcp_calculate_checksum();
    packet.payload();
}

// Chosen approach
pub fn with_traits(mut packet: impl TcpMethodsMut + Payload, lock: &mut StdoutLock) {
    println!("TCP: dst: {:?}", packet.tcp_destination_port()).unwrap();
    println!("TCP: src: {:?}", packet.tcp_source_port()).unwrap();
    packet.tcp_calculate_checksum();
    packet.payload();
}
```


# Data buffer length
Layers without explicit length fields expect the data to end with the underlying data buffer.
As soon as a length carrying layer (i.e. IPv4/6) is parsed, its length is used to calculate the data buffers actual end.

## Manipulating length
Using methods to change the length of upper layers modifies the lower layers appropriately.
One example is modifying TCP's payload offset header which carries its changes over to the underlying IPv4/6 layer.

# Layer method trait implementation
Layer methods interact with the underlying data buffer and the layer's metadata (length, offset) via the
`HeaderInformation`, `HeaderInformationMut`, `HeaderManipulation`, `BufferAccess` and `BufferAccessMut` traits.
Method call specific to a layer (e.g. length) are parameterized with a `Layer` which indicates which layer's
length is requested.
The stacked layer structs (e.g. `Eth`, `Arp`) forward the call to the next layer until the requested `Layer` matches the current layer
struct.
This approach requires every layer to only appear once in the layer structs stack but allows stacking layers in multiple
possible combinations (e.g. IPv6 -> optional IPv6 extensions -> TCP).

## Moving headers
Layer structs store their data's start relative to the general data start.
This allows moving layers below the expanding/shrinking layer without modification of the header start offset.
Layers above the modified layer are updated by the `increase_header_start_offset()` and `decrease_header_start_offset()`
methods of `HeaderInformationMut`.
