use crate::{
    types::{
        Export, GenericFields, Import, Info, Limits, NatsLimits, Permissions, SigningKey, UserScope,
    },
    Claim, ClaimType, Claims,
};
use derive_builder::Builder;
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct OperatorLimits {
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub nats: Option<NatsLimits>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub account: Option<AccountLimits>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub jetstream: Option<JetStreamLimits>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub tiered_limits: BTreeMap<String, Limits>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct JetStreamLimits {
    #[serde(rename = "mem_storage", skip_serializing_if = "Option::is_none")]
    pub memory_storage: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_storage: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub streams: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ack_pending: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_max_stream_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_max_stream_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes_required: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AccountLimits {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imports: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exports: Option<i64>,
    #[serde(rename = "wildcards", skip_serializing_if = "Option::is_none")]
    pub wildcard_exports: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disallow_bearer: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conn: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WeightedMapping {
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
}

type Mapping = BTreeMap<String, Vec<WeightedMapping>>;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExternalAuthorization {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_users: Option<BTreeSet<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<BTreeSet<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xkey: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct MsgTrace {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Builder)]
#[builder(setter(into), default)]
pub struct Account {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<Import>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exports: Vec<Export>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<OperatorLimits>,
    //#[serde(skip_serializing_if = "BTreeMap::is_empty")]
    //pub signing_keys: BTreeMap<String, UserScope>,
    #[serde(skip_serializing_if = "IndexSet::is_empty")]
    pub signing_keys: IndexSet<SigningKey>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub revocations: BTreeMap<String, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_permissions: Option<Permissions>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub mappings: Mapping,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<ExternalAuthorization>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub trace: Option<MsgTrace>,
    pub info: Option<Info>,
    #[serde(flatten)]
    pub generic_fields: GenericFields,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            generic_fields: GenericFields {
                claim_type: ClaimType::Account,
                ..Default::default()
            },
            info: None,
            default_permissions: None,
            imports: Vec::new(),
            exports: Vec::new(),
            signing_keys: IndexSet::new(),
            revocations: BTreeMap::new(),
            limits: None,
            mappings: BTreeMap::new(),
            authorization: None,
            trace: None,
        }
    }
}

impl Claim for Account {
    fn validate() {}
}

impl Account {
    pub fn new_claims(name: String, nkey: String) -> Claims<Account> {
        let account = Self::default();
        let mut claim = Claims::new(account);
        claim.name = Some(name);
        claim.sub = nkey;
        claim
    }
}
