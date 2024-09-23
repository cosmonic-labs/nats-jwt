use indexmap::IndexSet;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::time::Duration;

use crate::{user::UserPermissionLimits, ClaimType};

#[derive(Debug, Serialize, Deserialize, Clone, Hash, PartialEq, Eq)]
pub struct NatsLimits {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subs: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash, PartialEq, Eq)]
pub struct Limits {
    #[serde(flatten)]
    pub user_limits: UserLimits,
    #[serde(flatten)]
    pub nats_limits: NatsLimits,
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash, PartialEq, Eq)]
pub struct UserLimits {
    // TODO need to parse as an array of strings or a comma separated list, which means we need a
    // custom deserializer or just use a comma separated list since that's what nats actually uses
    src: Vec<String>,
    times: Vec<TimeRange>,
    locale: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash, PartialEq, Eq)]
pub struct TimeRange {
    start: String,
    end: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Import {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subject: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub account: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub token: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub to: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub local_subject: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub export_type: Option<ExportType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub share: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_trace: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct Export {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subject: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub export_type: Option<ExportType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_req: Option<bool>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub revocations: BTreeMap<String, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_type: Option<ResponseType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_threshold: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<ServiceLatency>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_token_position: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertise: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_trace: Option<bool>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub info: Option<Info>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "lowercase")]
pub enum ExportType {
    Unknown,
    #[default]
    Stream,
    Service,
}

impl Display for ExportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportType::Unknown => write!(f, "unknown"),
            ExportType::Stream => write!(f, "stream"),
            ExportType::Service => write!(f, "service"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceLatency {
    results: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Info {
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    info_url: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    Singleton,
    Stream,
    Chunked,
}

impl Display for ResponseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseType::Singleton => write!(f, "Singleton"),
            ResponseType::Stream => write!(f, "Stream"),
            ResponseType::Chunked => write!(f, "Chunked"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GenericFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(rename = "type")]
    pub claim_type: ClaimType,
    pub version: u32,
}

impl Default for GenericFields {
    fn default() -> Self {
        Self {
            tags: None,
            claim_type: ClaimType::Generic,
            version: 2,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Hash, PartialEq, Eq)]
pub struct Permissions {
    #[serde(default, rename = "pub")]
    pub publish: Permission,
    #[serde(default, rename = "sub")]
    pub subscribe: Permission,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resp: Option<ResponsePermission>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone, Hash, PartialEq, Eq)]
pub struct Permission {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Hash, PartialEq, Eq)]
pub struct ResponsePermission {
    #[serde(rename = "max")]
    pub max_messages: i64,
    #[serde(skip_serializing_if = "Duration::is_zero")]
    pub ttl: Duration,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Hash, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeType {
    #[default]
    UserScope,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, Hash, Eq, PartialEq)]
pub struct UserScope {
    pub kind: ScopeType,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<UserPermissionLimits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
#[serde(from = "KeyOrScope", into = "KeyOrScope")]
pub struct SigningKey {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<UserScope>,
}

impl From<KeyOrScope> for SigningKey {
    fn from(kos: KeyOrScope) -> Self {
        match kos {
            KeyOrScope::Key(k) => Self {
                key: k,
                scope: None,
            },
            KeyOrScope::Scope(s) => Self {
                key: s.key.clone(),
                scope: Some(s),
            },
        }
    }
}

impl From<SigningKey> for KeyOrScope {
    fn from(sk: SigningKey) -> Self {
        match sk.scope {
            Some(s) => KeyOrScope::Scope(s),
            None => KeyOrScope::Key(sk.key),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
enum KeyOrScope {
    Key(String),
    Scope(UserScope),
}

#[derive(Debug, Clone)]
enum SamplingRate {
    Headers,
    Percentage(u32),
}

impl Serialize for SamplingRate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            SamplingRate::Headers => serializer.serialize_str("headers"),
            SamplingRate::Percentage(p) => serializer.serialize_u32(*p),
        }
    }
}

impl<'de> Deserialize<'de> for SamplingRate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        enum Rates {
            String(String),
            U32(u32),
        }
        let data = Rates::deserialize(deserializer)?;
        match data {
            Rates::String(_s) => Ok(SamplingRate::Headers),
            Rates::U32(u) => Ok(SamplingRate::Percentage(u)),
        }
    }
}
