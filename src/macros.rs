macro_rules! generate_matching_enum_impl {
    (
        $(#[doc = $docs:literal])*
        #[repr($repr_type:ty)]
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant_name:ident = $variant_value:expr,
            )*
        }
    ) => {
         paste::paste! {
            $(#[doc = $docs])*
            $(#[$enum_meta])*
            #[repr($repr_type)]
            $enum_vis enum $enum_name {
                $(
                    $(#[$variant_meta])*
                    $variant_name = $variant_value,
                )*
            }

            impl core::fmt::Display for $enum_name {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "{:?}", self)
                }
            }

            impl core::convert::TryFrom<$repr_type> for $enum_name {
                type Error = [<NoRecognized $enum_name Error>];

                #[inline]
                fn try_from(value: $repr_type) -> core::result::Result<Self, [<NoRecognized $enum_name Error>]> {
                    match value {
                        $($variant_value => core::result::Result::Ok($enum_name::$variant_name),)*
                        _ => core::result::Result::Err([<NoRecognized $enum_name Error>] {
                            [<$enum_name:snake>]: value
                        }),
                    }
                }
            }

            #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
            $enum_vis struct [<NoRecognized $enum_name Error>] {
                 pub [<$enum_name:snake>]: $repr_type
            }

            impl core::fmt::Display for [<NoRecognized $enum_name Error>] {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    write!(f, "Not a valid header value , was: {:?}", self.[<$enum_name:snake>])
                }
            }

            #[cfg(all(feature = "error_trait", not(feature = "std")))]
            impl core::error::Error for [<NoRecognized $enum_name Error>] {}

            #[cfg(feature = "std")]
            impl std::error::Error for [<NoRecognized $enum_name Error>] {}

            // Kani verification to ensure the code does not panic on any input.
            #[cfg(kani)]
            mod [<$enum_name:lower _verification>] {
                use super::*;

                #[kani::proof]
                fn [<$enum_name:snake _proof>]() {
                    let try_value = kani::any::<$repr_type>();
                    match $enum_name::try_from(try_value) {
                        Ok(_) => {}
                        Err(err) => {
                            assert_eq!([<NoRecognized $enum_name Error>]{[<$enum_name:snake>]:try_value}, err);
                        }
                    }
                }
            }
        }
    }
}
pub(crate) use generate_matching_enum_impl;
