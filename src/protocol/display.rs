use std::fmt;

/// Wrapper implementing `Display` to convert the raw bytes of a payload into a printable
/// representation of its length and content (if UTF-8).
pub struct PrettyPayload<'a>(pub(super) &'a [u8]);

impl fmt::Display for PrettyPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match str::from_utf8(self.0) {
            Ok("") => write!(f, "<no payload>"),

            Ok(s) => write!(f, "{}-byte UTF-8 payload: {}", s.len(), s.escape_debug()),

            Err(_) => {
                let len = self.0.len();

                write!(f, "{len}-byte non-UTF-8 payload:")?;

                self.0.iter().enumerate().try_for_each(|(i, b)| {
                    if len <= 16 || i % 16 != 0 {
                        write!(f, " {b:02x}")
                    } else {
                        write!(f, "\n{b:02x}")
                    }
                })
            }
        }
    }
}

/// Wrapper implementing `Display` for thousands-separator formatting.
pub(super) struct ThousandsSeparated<T>(T);

pub(super) trait WithThousandsSeparators: Sized
where
    ThousandsSeparated<Self>: fmt::Display,
{
    /// Wraps `self` in `ThousandsSeparated` for pretty printing with thousands separators.
    fn with_thousands_separators(self) -> ThousandsSeparated<Self> { ThousandsSeparated(self) }
}

impl<T> WithThousandsSeparators for T where ThousandsSeparated<T>: fmt::Display {}

/// Generates `fmt::Display for ThousandsSeparated<T>` implementations for all types passed as
/// comma-separated arguments. Limited to unsigned integer types.
macro_rules! impl_display_thousands_separated {
    ($($t:ty),+ $(,)?) => {
        $(
            impl fmt::Display for ThousandsSeparated<$t> {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    match (self.0 / 1000, self.0 % 1000) {
                        (0, rem) => write!(f, "{rem}"),
                        (thousands, rem) => write!(f, "{},{rem:03}", ThousandsSeparated(thousands)),
                    }
                }
            }
        )+
    };
}

impl_display_thousands_separated!(u16, u32);

#[cfg(test)]
mod tests {
    use {
        super::*,
        std::{num::ParseIntError, str::FromStr},
    };

    /// Removes commas from `s`, parses the result as `T`, and then adds commas back to that result.
    fn comma_round_trip<T>(s: &str) -> Result<String, T::Err>
    where
        T: FromStr,
        ThousandsSeparated<T>: fmt::Display,
    {
        s.replace(',', "")
            .parse::<T>()
            .map(|parsed| parsed.with_thousands_separators().to_string())
    }

    #[test]
    fn separates_all_widths() -> Result<(), ParseIntError> {
        for s in ["65,535", "4,321", "321", "21", "1", "0"] {
            assert_eq!(s, comma_round_trip::<u16>(s)?);
        }

        for s in [
            "4,294,967,295",
            "987,654,321",
            "87,654,321",
            "7,654,321",
            "654,321",
            "54,321",
            "4,321",
            "321",
            "21",
            "1",
            "0",
        ] {
            assert_eq!(s, comma_round_trip::<u32>(s)?);
        }

        Ok(())
    }

    #[test]
    fn handles_trailing_and_internal_zeros() -> Result<(), ParseIntError> {
        for s in ["60,000", "60,001", "4,000", "4,001", "300", "301", "20"] {
            assert_eq!(s, comma_round_trip::<u16>(s)?);
        }

        for s in [
            "4,000,000,000",
            "4,000,000,001",
            "900,000,000",
            "900,000,001",
            "80,000,000",
            "80,000,001",
            "4,000",
            "4,001",
            "300",
            "301",
            "20",
        ] {
            assert_eq!(s, comma_round_trip::<u32>(s)?);
        }

        Ok(())
    }
}
