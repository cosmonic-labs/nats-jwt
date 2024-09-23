use crate::types::{GenericFields, Limits, Permissions};
use crate::{Claim, ClaimType, Claims};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_account: Option<String>,
    #[serde(flatten)]
    pub permissions: UserPermissionLimits,
    #[serde(flatten)]
    pub generic_fields: GenericFields,
}

impl Claim for User {
    fn validate() {}
}

impl Default for User {
    fn default() -> Self {
        Self {
            permissions: UserPermissionLimits::default(),
            issuer_account: None,
            generic_fields: GenericFields {
                claim_type: ClaimType::User,
                ..Default::default()
            },
        }
    }
}

impl User {
    pub fn new_claims(name: String, nkey: String) -> Claims<User> {
        let user = Self::default();
        let mut claim = Claims::new(user);
        claim.name = Some(name);
        claim.sub = nkey;
        claim
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, Hash, Eq, PartialEq)]
pub struct UserPermissionLimits {
    #[serde(flatten)]
    pub permissions: Permissions,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub limits: Option<Limits>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_token: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_connection_types: Option<Vec<String>>,
}
