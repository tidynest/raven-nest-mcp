//! Wall-clock timestamps and their text forms.
//!
//! Every timestamp the server stores or prints goes through [`Timestamp`], so
//! the three shapes below are defined once. They are the shapes older releases
//! wrote, and files on disk depend on them:
//!
//! | Use | Shape |
//! |-----|-------|
//! | stored records (serde) | `2026-11-26T16:26:55.311147711Z` |
//! | audit log, reports, cookie file ([`Timestamp::to_rfc3339`]) | `2026-11-26T16:26:55.311147711+00:00` |
//! | tool text (`Display`) | `2026-11-26 16:26:55.311147711 UTC` |
//!
//! The fraction has 0, 3, 6 or 9 digits, whichever is the shortest that loses
//! nothing.

use jiff::tz::{Offset, TimeZone};
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;

/// An instant in UTC with nanosecond precision. Defaults to the Unix epoch.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct Timestamp(jiff::Timestamp);

impl Timestamp {
    /// The current time.
    pub fn now() -> Self {
        Self(jiff::Timestamp::now())
    }

    /// The instant `second` whole seconds after the Unix epoch.
    ///
    /// # Panics
    /// If `second` is outside the years -9999 to 9999.
    pub fn from_second(second: i64) -> Self {
        Self(jiff::Timestamp::from_second(second).expect("second within the supported range"))
    }

    /// Whole seconds since the Unix epoch.
    pub fn as_second(self) -> i64 {
        self.0.as_second()
    }

    /// RFC 3339 in UTC with a numeric offset, e.g. `2026-11-26T16:26:55.311+00:00`.
    pub fn to_rfc3339(self) -> String {
        self.render('T', "+00:00")
    }

    /// `{date}{separator}{time}{fraction}{suffix}` in UTC.
    fn render(self, separator: char, suffix: &str) -> String {
        let utc = Offset::UTC.to_datetime(self.0);
        let fraction = match utc.subsec_nanosecond() {
            0 => String::new(),
            n if n % 1_000_000 == 0 => format!(".{:03}", n / 1_000_000),
            n if n % 1_000 == 0 => format!(".{:06}", n / 1_000),
            n => format!(".{n:09}"),
        };
        format!(
            "{}{separator}{:02}:{:02}:{:02}{fraction}{suffix}",
            utc.date(),
            utc.hour(),
            utc.minute(),
            utc.second()
        )
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render(' ', " UTC"))
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.render('T', "Z"))
    }
}

/// The current time in the system's local time zone as `2026-11-26_172656`,
/// for use in file names.
///
/// The zone comes from `TZ`, then `/etc/localtime`. A `TZ` that names no
/// known zone is skipped, and UTC is the last resort.
pub fn local_file_stamp() -> String {
    let zone = TimeZone::try_system()
        .ok()
        .or_else(|| TimeZone::tzif("localtime", &std::fs::read("/etc/localtime").ok()?).ok())
        .unwrap_or(TimeZone::UTC);
    zone.to_datetime(jiff::Timestamp::now())
        .strftime("%Y-%m-%d_%H%M%S")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(second: i64, nanosecond: i32) -> Timestamp {
        Timestamp(jiff::Timestamp::new(second, nanosecond).unwrap())
    }

    /// Expected strings were produced by chrono 0.4.44, which this module
    /// replaced: serde, `to_rfc3339` and `Display` of `DateTime<Utc>`.
    #[test]
    fn text_forms_match_the_ones_already_on_disk() {
        let cases = [
            (0, "2026-11-26T16:26:55", "2026-11-26 16:26:55"),
            (
                311_000_000,
                "2026-11-26T16:26:55.311",
                "2026-11-26 16:26:55.311",
            ),
            (
                311_147_000,
                "2026-11-26T16:26:55.311147",
                "2026-11-26 16:26:55.311147",
            ),
            (
                311_147_711,
                "2026-11-26T16:26:55.311147711",
                "2026-11-26 16:26:55.311147711",
            ),
            (
                100_000_000,
                "2026-11-26T16:26:55.100",
                "2026-11-26 16:26:55.100",
            ),
            (
                10,
                "2026-11-26T16:26:55.000000010",
                "2026-11-26 16:26:55.000000010",
            ),
        ];
        for (nanosecond, iso, spaced) in cases {
            let ts = at(1_795_710_415, nanosecond);
            assert_eq!(serde_json::to_string(&ts).unwrap(), format!("\"{iso}Z\""));
            assert_eq!(ts.to_rfc3339(), format!("{iso}+00:00"));
            assert_eq!(ts.to_string(), format!("{spaced} UTC"));
        }
    }

    #[test]
    fn stored_form_round_trips() {
        for nanosecond in [0, 311_000_000, 311_147_000, 311_147_711] {
            let ts = at(1_795_710_415, nanosecond);
            let json = serde_json::to_string(&ts).unwrap();
            assert_eq!(serde_json::from_str::<Timestamp>(&json).unwrap(), ts);
        }
    }

    #[test]
    fn reads_any_utc_offset_as_the_same_instant() {
        let z: Timestamp = serde_json::from_str("\"2024-01-01T00:00:00Z\"").unwrap();
        let plus: Timestamp = serde_json::from_str("\"2024-01-01T02:00:00+02:00\"").unwrap();
        assert_eq!(z, plus);
        assert_eq!(z.as_second(), 1_704_067_200);
    }

    #[test]
    fn default_is_the_unix_epoch() {
        assert_eq!(Timestamp::default(), Timestamp::from_second(0));
        assert_eq!(Timestamp::default().to_string(), "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn local_file_stamp_has_the_report_name_shape() {
        let stamp = local_file_stamp();
        let shape: String = stamp
            .chars()
            .map(|c| if c.is_ascii_digit() { '0' } else { c })
            .collect();
        assert_eq!(shape, "0000-00-00_000000");
    }
}
