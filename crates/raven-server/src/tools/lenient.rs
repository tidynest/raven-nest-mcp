//! Lenient serde deserializers for LLM-generated tool arguments.
//!
//! LLMs sometimes serialize numbers as JSON strings (e.g. `"2"` instead of `2`).
//! These helpers accept both forms transparently, avoiding deserialization errors
//! that would otherwise surface as unhelpful MCP error codes.

use serde::{Deserialize, Deserializer, de};
use std::fmt;
use std::str::FromStr;

/// Deserializes `Option<T>` accepting both numeric and string-encoded values.
///
/// Handles: absent/`null` -> `None`, `2` -> `Some(2)`, `"2"` -> `Some(2)`.
pub fn option_number<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + FromStr,
    <T as FromStr>::Err: fmt::Display,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumOrStr<V> {
        Num(V),
        Str(String),
    }

    match Option::<NumOrStr<T>>::deserialize(deserializer)? {
        None => Ok(None),
        Some(NumOrStr::Num(n)) => Ok(Some(n)),
        Some(NumOrStr::Str(s)) => s.parse::<T>().map(Some).map_err(de::Error::custom),
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct TestStruct {
        #[serde(default, deserialize_with = "super::option_number")]
        value: Option<u8>,
    }

    #[test]
    fn accepts_number() {
        let s: TestStruct = serde_json::from_str(r#"{"value": 5}"#).unwrap();
        assert_eq!(s.value, Some(5));
    }

    #[test]
    fn accepts_string() {
        let s: TestStruct = serde_json::from_str(r#"{"value": "5"}"#).unwrap();
        assert_eq!(s.value, Some(5));
    }

    #[test]
    fn accepts_null() {
        let s: TestStruct = serde_json::from_str(r#"{"value": null}"#).unwrap();
        assert_eq!(s.value, None);
    }

    #[test]
    fn accepts_missing() {
        let s: TestStruct = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(s.value, None);
    }

    #[test]
    fn rejects_invalid_string() {
        let result = serde_json::from_str::<TestStruct>(r#"{"value": "abc"}"#);
        assert!(result.is_err());
    }
}
