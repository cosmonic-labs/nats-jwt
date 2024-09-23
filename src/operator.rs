use crate::{
    types::{
        Export, GenericFields, Import, Info, Limits, NatsLimits, Permissions, SigningKey, UserScope,
    },
    Claim, ClaimType, Claims,
};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Builder)]
#[builder(setter(into), default)]
pub struct Operator {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signing_keys: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_server_url: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub operator_service_urls: Vec<String>,
    pub system_account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assert_server_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strict_signing_key_usage: Option<bool>,

    #[serde(flatten)]
    pub generic_fields: GenericFields,
}

impl Default for Operator {
    fn default() -> Self {
        Self {
            generic_fields: GenericFields {
                claim_type: ClaimType::Operator,
                ..Default::default()
            },
            signing_keys: Vec::new(),
            account_server_url: None,
            strict_signing_key_usage: None,
            operator_service_urls: Vec::new(),
            system_account: None,
            assert_server_version: None,
        }
    }
}

impl Claim for Operator {
    fn validate() {}
}

impl Operator {
    pub fn new_claims(name: String, nkey: String) -> Claims<Operator> {
        let operator = Self::default();
        let mut claim = Claims::new(operator);
        claim.name = Some(name);
        claim.sub = nkey;
        claim
    }
}
