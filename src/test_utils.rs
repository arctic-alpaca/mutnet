#[cfg(test)]
pub(crate) fn copy_into_slice(buffer: &mut [u8], data: &[u8], at: usize) {
    for (i, byte) in data.iter().enumerate() {
        buffer[at + i] = *byte;
    }
}
