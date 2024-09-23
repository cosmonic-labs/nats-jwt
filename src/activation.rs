use crate::{
    types::{ExportType, GenericFields},
    Claim, ClaimType, Claims,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512_256};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Activation {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub import_subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import_type: Option<ExportType>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub issuer_account: String,

    #[serde(flatten)]
    pub generic_fields: GenericFields,
}

impl Claim for Activation {
    fn validate() {}
}

impl Default for Activation {
    fn default() -> Self {
        Self {
            import_subject: "".to_string(),
            import_type: None,
            issuer_account: "".to_string(),
            generic_fields: GenericFields {
                claim_type: ClaimType::Activation,
                ..Default::default()
            },
        }
    }
}

impl Activation {
    pub fn new_claims(name: String, nkey: String) -> Claims<Activation> {
        let account = Self::default();
        let mut claim = Claims::new(account);
        claim.name = Some(name);
        claim.sub = nkey;
        claim
    }

    pub fn hash(claims: Claims<Activation>) -> anyhow::Result<String> {
        if claims.iss.is_empty() || claims.sub.is_empty() || claims.nats.import_subject.is_empty() {
            return Err(anyhow::anyhow!("not enough data in the claim to hash"));
        }

        let subject = Self::clean_subject(&claims.nats.import_subject);
        let base = format!("{}{}{}", claims.iss, claims.sub, subject);
        let mut hasher = Sha512_256::new();
        hasher.update(base.as_bytes());
        let result = hasher.finalize();
        let encoded = BASE32_NOPAD.encode(&result);

        Ok(encoded)
    }

    fn clean_subject(subject: &str) -> String {
        let split: Vec<&str> = subject.split('.').collect();
        let mut cleaned = String::new();

        for (i, tok) in split.iter().enumerate() {
            if *tok == "*" || *tok == ">" {
                if i == 0 {
                    cleaned = "_".to_string();
                    break;
                }
                cleaned = split[..i].join(".");
                break;
            }
        }

        if cleaned.is_empty() {
            cleaned = subject.to_string();
        }

        cleaned
    }
}
