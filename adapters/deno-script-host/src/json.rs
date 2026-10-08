//! The `Value` ⇄ JSON crossing: one conversion, in both directions, so the
//! wire never decides what a step's numbers are.

use ks_core::ports::script_host::{Value, Values};
use serde_json::{Map, Number};

/// A [`Value`] as JSON. Numbers are `f64` on both sides of this boundary, so a
/// step sees `3` and gives back `3`.
pub fn value_to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Null => serde_json::Value::Null,
        Value::Bool(flag) => serde_json::Value::Bool(*flag),
        Value::Number(number) => {
            serde_json::Value::Number(Number::from_f64(*number).unwrap_or_else(|| Number::from(0)))
        }
        Value::String(text) => serde_json::Value::String(text.clone()),
        Value::List(items) => serde_json::Value::Array(items.iter().map(value_to_json).collect()),
        Value::Map(entries) => {
            let mut map = Map::new();
            for (name, entry) in entries {
                map.insert(name.clone(), value_to_json(entry));
            }
            serde_json::Value::Object(map)
        }
    }
}

/// A [`Values`] map as a JSON object.
pub fn values_to_json(values: &Values) -> serde_json::Value {
    let mut map = Map::new();
    for (name, value) in values {
        map.insert(name.clone(), value_to_json(value));
    }
    serde_json::Value::Object(map)
}

/// JSON as a [`Value`]. An object is a [`Value::Map`] and an array a
/// [`Value::List`]; a number that is not finite has no JSON spelling and comes
/// back as null rather than as a lie.
pub fn value_from_json(json: &serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(flag) => Value::Bool(*flag),
        serde_json::Value::Number(number) => Value::Number(number.as_f64().unwrap_or(f64::NAN)),
        serde_json::Value::String(text) => Value::String(text.clone()),
        serde_json::Value::Array(items) => Value::List(items.iter().map(value_from_json).collect()),
        serde_json::Value::Object(entries) => Value::Map(
            entries.iter().map(|(name, value)| (name.clone(), value_from_json(value))).collect(),
        ),
    }
}

/// A JSON object as [`Values`]; anything else is `None`, because a step's
/// outputs are an object by contract.
pub fn values_from_json(json: &serde_json::Value) -> Option<Values> {
    match value_from_json(json) {
        Value::Map(entries) => Some(entries),
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_survive_the_json_round_trip() {
        let values: Values = [
            ("flag".to_string(), Value::Bool(true)),
            ("count".to_string(), Value::Number(3.0)),
            ("name".to_string(), Value::from("conformance")),
            ("nothing".to_string(), Value::Null),
            ("tags".to_string(), Value::List(vec![Value::from("web"), Value::from("app")])),
            (
                "labels".to_string(),
                Value::Map([("env".to_string(), Value::from("staging"))].into_iter().collect()),
            ),
        ]
        .into_iter()
        .collect();
        let json = values_to_json(&values);
        assert_eq!(values_from_json(&json).as_ref(), Some(&values));
    }

    #[test]
    fn a_non_object_is_not_a_step_result() {
        assert_eq!(values_from_json(&serde_json::json!([1, 2])), None);
        assert_eq!(values_from_json(&serde_json::json!("ok")), None);
        assert_eq!(values_from_json(&serde_json::json!({})), Some(Values::new()));
    }
}
