//! Convenience structs for commonly defined fields in claims.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

/// Generic [JWT claims](https://tools.ietf.org/html/rfc7519#page-8) with
/// defined fields for registered and private claims.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    #[serde(flatten)]
    pub registered: RegisteredClaims,
    #[serde(flatten)]
    pub private: BTreeMap<String, serde_json::Value>,
}

impl Claims {
    pub fn new(registered: RegisteredClaims) -> Self {
        Claims {
            registered,
            private: BTreeMap::new(),
        }
    }
}

pub type SecondsSinceEpoch = u64;

// From https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
// "In the general case, the "aud" value is an array of case-
// sensitive strings, each containing a StringOrURI value.  In the
// special case when the JWT has one audience, the "aud" value MAY be a
// single case-sensitive string containing a StringOrURI value."
fn parse_audience<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
    where
        D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audience<'a> {
        Str(&'a str),
        Vec(Vec<String>),
        None,
    }

    Ok(match Audience::deserialize(deserializer)? {
        Audience::Str(v) => Some(vec![v.to_string()]),
        Audience::Vec(v) => Some(v),
        Audience::None => None,
    })
}

/// Registered claims according to the
/// [JWT specification](https://tools.ietf.org/html/rfc7519#page-9).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RegisteredClaims {
    #[serde(rename = "iss", skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    #[serde(rename = "sub", skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    #[serde(rename = "aud", skip_serializing_if = "Option::is_none", deserialize_with="parse_audience", default)]
    pub audience: Option<Vec<String>>,

    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    pub expiration: Option<SecondsSinceEpoch>,

    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<SecondsSinceEpoch>,

    #[serde(rename = "iat", skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<SecondsSinceEpoch>,

    #[serde(rename = "jti", skip_serializing_if = "Option::is_none")]
    pub json_web_token_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::claims::Claims;
    use crate::error::Error;
    use crate::{FromBase64, ToBase64};
    use serde_json::Value;
    use std::default::Default;

    // {"iss":"mikkyang.com","exp":1302319100,"aud":["audience"],"custom_claim":true}
    const ENCODED_PAYLOAD: &str =
        "eyJpc3MiOiJtaWtreWFuZy5jb20iLCJleHAiOjEzMDIzMTkxMDAsImF1ZCI6WyJhdWRpZW5jZSJdLCJjdXN0b21fY2xhaW0iOnRydWV9";

    #[test]
    fn registered_claims() -> Result<(), Error> {
        let claims = Claims::from_base64(ENCODED_PAYLOAD)?;

        assert_eq!(claims.registered.issuer.unwrap(), "mikkyang.com");
        assert_eq!(claims.registered.expiration.unwrap(), 1302319100);
        assert_eq!(claims.registered.audience.unwrap(), vec!["audience"]);
        Ok(())
    }

    #[test]
    fn audience_special_case() -> Result<(), Error> {
        // {"iss":"mikkyang.com","exp":1302319100,"aud":"audience","custom_claim":true}
        let encoded_payload: &str =
            "eyJpc3MiOiJtaWtreWFuZy5jb20iLCJleHAiOjEzMDIzMTkxMDAsImF1ZCI6ImF1ZGllbmNlIiwiY3VzdG9tX2NsYWltIjp0cnVlfQ==";

        let claims = Claims::from_base64(encoded_payload)?;

        assert_eq!(claims.registered.issuer.unwrap(), "mikkyang.com");
        assert_eq!(claims.registered.expiration.unwrap(), 1302319100);
        assert_eq!(claims.registered.audience.unwrap(), vec!["audience"]);
        Ok(())
    }

    #[test]
    fn private_claims() -> Result<(), Error> {
        let claims = Claims::from_base64(ENCODED_PAYLOAD)?;

        assert_eq!(claims.private["custom_claim"], Value::Bool(true));
        Ok(())
    }

    #[test]
    fn roundtrip() -> Result<(), Error> {
        let mut claims: Claims = Default::default();
        claims.registered.issuer = Some("mikkyang.com".into());
        claims.registered.expiration = Some(1302319100);
        let enc = claims.to_base64()?;
        assert_eq!(claims, Claims::from_base64(&*enc)?);
        Ok(())
    }
}
