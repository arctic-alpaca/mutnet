use crate::ipv6_extensions::{Ipv6ExtensionIndexOutOfBoundsError, Ipv6ExtensionMetadata};

pub(crate) trait Ipv6ExtMetaData<const MAX_EXTENSIONS: usize> {
    fn extensions_array(&self) -> &[Ipv6ExtensionMetadata; MAX_EXTENSIONS];
    fn extension(
        &self,
        idx: usize,
    ) -> Result<Ipv6ExtensionMetadata, Ipv6ExtensionIndexOutOfBoundsError>;
    fn extensions_amount(&self) -> usize;
}

pub(crate) trait Ipv6ExtMetaDataMut<const MAX_EXTENSIONS: usize> {
    fn extensions_array_mut(&mut self) -> &mut [Ipv6ExtensionMetadata; MAX_EXTENSIONS];
}
