use crate::{AttestationError, Result};
use serde::Serialize;
use serde_json::{Number, Value};
use sha2::{Digest, Sha256};

pub const MAX_SAFE_JSON_INT: u64 = 9_007_199_254_740_991;

pub fn canonical_digest<T: Serialize>(value: &T) -> Result<String> {
    let json = canonical_json(value)?;
    Ok(sha256_digest(json.as_bytes()))
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<String> {
    let value = serde_json::to_value(value)?;
    let mut out = String::new();
    write_value(&value, &mut out)?;
    Ok(out)
}

pub fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity("sha256:".len() + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn write_value(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
        Value::Number(number) => write_number(number, out)?,
        Value::String(value) => out.push_str(&serde_json::to_string(value)?),
        Value::Array(values) => {
            out.push('[');
            for (idx, item) in values.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            // RFC 8785/JCS follows ECMAScript property ordering: compare raw
            // UTF-16 code units, not UTF-8 bytes or Unicode scalar values.
            entries.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));

            out.push('{');
            for (idx, (key, value)) in entries.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key)?);
                out.push(':');
                write_value(value, out)?;
            }
            out.push('}');
        }
    }

    Ok(())
}

fn write_number(number: &Number, out: &mut String) -> Result<()> {
    if let Some(value) = number.as_u64() {
        if value > MAX_SAFE_JSON_INT {
            return Err(AttestationError::UnsafeInteger(value));
        }
        out.push_str(&value.to_string());
        return Ok(());
    }

    if let Some(value) = number.as_i64() {
        let abs = value.unsigned_abs();
        if abs > MAX_SAFE_JSON_INT {
            return Err(AttestationError::UnsafeInteger(abs));
        }
        out.push_str(&value.to_string());
        return Ok(());
    }

    Err(AttestationError::NonCanonicalFloat)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_object_keys() {
        let value = json!({"b": 1, "a": {"d": true, "c": false}});
        assert_eq!(
            canonical_json(&value).unwrap(),
            r#"{"a":{"c":false,"d":true},"b":1}"#
        );
    }

    #[test]
    fn rejects_numbers_above_json_safe_integer_range() {
        let value = json!({"millis": MAX_SAFE_JSON_INT + 1});
        assert!(matches!(
            canonical_json(&value),
            Err(AttestationError::UnsafeInteger(_))
        ));
    }

    #[test]
    fn canonical_json_orders_object_keys_by_utf16_code_units() {
        let value = json!({"\u{e000}": 2, "\u{10000}": 1});

        assert_eq!(canonical_json(&value).unwrap(), "{\"𐀀\":1,\"\":2}");
    }
}
