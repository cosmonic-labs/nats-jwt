use crate::{types::GenericFields, Claim, ClaimType, Claims};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ClientInfo {
    pub host: String,
    pub id: u64,
    pub user: String,
    pub name: Option<String>,
    pub tags: Option<Vec<String>>,
    pub name_tag: String,
    pub kind: String,
    #[serde(rename = "type")]
    pub client_type: String,
    pub mqtt: Option<String>,
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ConnectOpts {
    pub jwt: Option<String>,
    pub nkey: Option<String>,
    pub sig: Option<String>,
    pub auth_token: Option<String>,
    pub user: Option<String>,
    pub pass: Option<String>,
    pub name: Option<String>,
    pub lang: Option<String>,
    pub version: Option<String>,
    pub protocol: u32,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ClientTLS {
    version: String,
    cipher: String,
    certs: Vec<String>,
    verified_chains: Vec<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "snake_case")]
pub struct AuthRequest {
    #[serde(rename = "server_id")]
    pub server: ServerID,
    pub user_nkey: String,
    pub client_info: ClientInfo,
    pub connect_opts: ConnectOpts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_tls: Option<ClientTLS>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_nonce: Option<String>,

    #[serde(flatten)]
    pub generic_fields: GenericFields,
}

impl AuthRequest {
    fn new() -> Self {
        Self {
            server: ServerID::default(),
            user_nkey: String::new(),
            client_info: ClientInfo::default(),
            connect_opts: ConnectOpts::default(),
            client_tls: None,
            request_nonce: None,
            generic_fields: GenericFields::default(),
        }
    }
}

impl Claim for AuthRequest {
    fn validate() {}
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ServerID {
    pub name: String,
    pub host: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
    // TODO should this be an indexset?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeSet<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xkey: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthResponse {
    pub jwt: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_account: Option<String>,
    #[serde(flatten)]
    pub generic_fields: GenericFields,
}

impl AuthResponse {
    pub fn generic_claim(nkey: String) -> Claims<AuthResponse> {
        let mut claim = Claims::new(AuthResponse {
            jwt: String::new(),
            error: String::new(),
            issuer_account: None,
            generic_fields: GenericFields {
                claim_type: ClaimType::AuthorizationResponse,
                version: 2,
                ..Default::default()
            },
        });
        claim.sub = nkey;
        claim
    }
}

impl Claim for AuthResponse {
    fn validate() {}
}
