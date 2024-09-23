use std::{fmt::Display, time::UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use data_encoding::BASE32_NOPAD;
use nkeys::KeyPair;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha512_256};

pub mod account;
pub mod activation;
pub mod authorization;
pub mod operator;
pub mod types;
pub mod user;
pub mod validation;

const HEADER_TYPE: &str = "JWT";
const HEADER_ALGORITHM: &str = "ed25519-nkey";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClaimsHeader {
    #[serde(rename = "typ")]
    header_type: String,

    #[serde(rename = "alg")]
    algorithm: String,
}

impl ClaimsHeader {
    pub fn from_str(header: &str) -> Result<Self> {
        let header: ClaimsHeader = decode_claims(header)?;
        if header.header_type != HEADER_TYPE {
            return Err(anyhow::anyhow!("unsupported type {}", header.header_type));
        }
        if header.algorithm != HEADER_ALGORITHM {
            return Err(anyhow::anyhow!(
                "unsupported algorithm {}",
                header.algorithm
            ));
        }
        Ok(header)
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ClaimType {
    Operator,
    Account,
    User,
    Activation,
    AuthorizationRequest,
    AuthorizationResponse,
    #[default]
    Generic,
}

impl Display for ClaimType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimType::Operator => write!(f, "operator"),
            ClaimType::Account => write!(f, "account"),
            ClaimType::User => write!(f, "user"),
            ClaimType::Activation => write!(f, "activation"),
            ClaimType::AuthorizationRequest => write!(f, "authorization_request"),
            ClaimType::AuthorizationResponse => write!(f, "authorization_response"),
            ClaimType::Generic => write!(f, "generic"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims<T> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    pub iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub iss: String,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub nats: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sub: String,
}

impl<T> Claims<T>
where
    T: Claim,
{
    fn new(nats: T) -> Claims<T> {
        Self {
            aud: None,
            exp: None,
            iat: 0,
            id: None,
            iss: String::new(),
            jti: String::new(),
            name: None,
            nats,
            nbf: None,
            sub: String::new(),
        }
    }
}

impl<T> Claims<T>
where
    T: Claim + DeserializeOwned + Serialize + Clone,
{
    pub fn payload(&self) -> &T {
        &self.nats
    }

    pub fn payload_mut(&mut self) -> &mut T {
        &mut self.nats
    }

    pub fn decode(token: &str) -> Result<Claims<T>> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow::anyhow!("Invalid JWT"));
        }

        let _header = ClaimsHeader::from_str(parts[0])?;
        let payload: Claims<T> = decode_claims(parts[1])?;
        let signature = parts[2].to_string();
        let decoded_sig = URL_SAFE_NO_PAD.decode(signature.as_bytes())?;
        let kp = KeyPair::from_public_key(&payload.iss)?;
        kp.verify(
            token[0..token.len() - signature.len() - 1].as_bytes(),
            &decoded_sig,
        )?;

        Ok(payload)
    }

    pub fn encode(&self, key_pair: &KeyPair) -> Result<String> {
        let jwt: JWT<T> = JWT {
            header: ClaimsHeader {
                header_type: HEADER_TYPE.to_string(),
                algorithm: HEADER_ALGORITHM.to_string(),
            },
            payload: self.clone(),
            signature: String::new(),
        };

        jwt.encode(key_pair)
    }
}

pub trait Claim {
    fn validate();
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct JWT<T> {
    pub header: ClaimsHeader,
    pub payload: Claims<T>,
    pub signature: String,
}

impl<T> JWT<T>
where
    T: Claim + DeserializeOwned + Serialize + Clone,
{
    pub fn encode(&self, key: &nkeys::KeyPair) -> Result<String> {
        let hdr = encode_jwt_segment(&self.header)?;
        let mut c = self.payload.clone();
        c.iat = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        c.iss = key.public_key();
        c.jti = "".to_string();

        let encoded_claim = serde_json::to_string(&c).unwrap();
        let mut hasher = Sha512_256::new();
        hasher.update(encoded_claim.as_bytes());
        let result = hasher.finalize();
        let jti = BASE32_NOPAD.encode(&result);
        c.jti = jti;

        let claims = encode_jwt_segment(&c)?;
        let intermediate = format!("{}.{}", hdr, claims);
        let sig = key.sign(intermediate.as_bytes())?;
        let s = URL_SAFE_NO_PAD.encode(sig);
        Ok(format!("{}.{}", intermediate, s))
    }

    pub fn decode(token: String) -> Result<Self> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow::anyhow!("Invalid JWT"));
        }

        let header = decode_jwt_segment::<ClaimsHeader>(parts[0])?;
        let payload = decode_claims(parts[1])?;
        let signature = parts[2].to_string();

        Ok(Self {
            header,
            payload,
            signature,
        })
    }
}

fn encode_jwt_segment<T: Serialize>(input: &T) -> Result<String> {
    let encoded = serde_json::to_string(input)?;
    Ok(URL_SAFE_NO_PAD.encode(encoded.as_bytes()))
}

fn decode_jwt_segment<D: DeserializeOwned>(input: &str) -> Result<D> {
    let decoded = URL_SAFE_NO_PAD.decode(input.as_bytes())?;
    serde_json::from_slice(&decoded).context("Failed to decode JWT segment")
}

fn decode_claims<T: DeserializeOwned>(input: &str) -> Result<T> {
    let decoded = URL_SAFE_NO_PAD.decode(input.as_bytes())?;
    serde_json::from_slice(&decoded).map_err(|e| e.into())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::authorization::AuthRequest;
    use crate::user::User;

    #[test]
    fn test_encode() {
        let user_key = KeyPair::new_user();
        let account_key = KeyPair::new_account();
        let signer = KeyPair::new_account();
        let mut user = User::new_claims("test".to_string(), user_key.public_key());
        user.nats.issuer_account = Some(account_key.public_key());
        let enc = user.encode(&signer).unwrap();
        println!("{}", enc);

        let dec = Claims::<User>::decode(&enc).unwrap();
        assert_eq!(dec.payload().issuer_account, Some(account_key.public_key()));
        assert_eq!(dec.name, Some("test".to_string()));
        assert_eq!(dec.sub, user_key.public_key());
        assert_eq!(dec.iss, signer.public_key());
    }

    #[test]
    fn test_decode() {
        let token = r#"
{
    "aud": "nats-authorization-request",
    "exp": 1724095784,
    "iat": 1724095782,
    "iss": "NCLH2BAHSW2ASMRX7IIVUPQRUDTC556SMEY5L7PWNHZUJYQ7UDV7C7BA",
    "jti": "ZSNBV24DRMSOCNSGUR45P6S3MGJQ4GRHQXNO6VAPIIKLNV6PYRCA",
    "nats": {
        "client_info": {
            "host": "127.0.0.1",
            "id": 21,
            "kind": "Client",
            "name": "NATS CLI Version development",
            "name_tag": "wasmCloud User Auth-registration",
            "nonce": "6KZMq4gzqULs8Cw",
            "type": "nats",
            "user": "UCB7G4JWCLUIJE7552IRU3EUCPYHSDGIEBANNQ2DLPS4GHKNFOQZORUA"
        },
        "connect_opts": {
            "auth_token": "test",
            "jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJUUkdDNVJKWlpLTkpZUEJLRlNNVFFNU05YR0hZTzVENkFHUDU3WlNYUVpKMzJCUVNXTEpRIiwiaWF0IjoxNzI0MDkxNDQ3LCJpc3MiOiJBRDVKWEEyV1RaMk5ZSlBPUzZLUUdSUklNRjNSU0NaR0tTVUlLWVc0UUVVUlhVUk1GT0VDM0xMUSIsIm5hbWUiOiJ3YXNtQ2xvdWQgVXNlciBBdXRoLXJlZ2lzdHJhdGlvbiIsInN1YiI6IlVDQjdHNEpXQ0xVSUpFNzU1MklSVTNFVUNQWUhTREdJRUJBTk5RMkRMUFM0R0hLTkZPUVpPUlVBIiwibmF0cyI6eyJwdWIiOnsiZGVueSI6WyJcdTAwM2UiXX0sInN1YiI6eyJkZW55IjpbIlx1MDAzZSJdfSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwiaXNzdWVyX2FjY291bnQiOiJBQ1ZVS1NBVkRKVjY1QVpMTlJQU0tGSlBZMjJXTlJaSVhGVU9SWFhLVlkyTEhYTTJKTUtMN0c0RiIsInR5cGUiOiJ1c2VyIiwidmVyc2lvbiI6Mn19.1_DxwilYeT2JkCKV1H0Oykp9Upums9F_RM0E8e6W-XxEtGXgYN-boXNkokIC6XjE5dkkSBZSVXz53p5JFK4UDQ",
            "lang": "go",
            "name": "NATS CLI Version development",
            "protocol": 1,
            "sig": "cM53BpZmXibyMbtOJtPYpcMjYdWb33dAt0XOhCjay1aapoSUEx27lbE08MMHFzJAuuR7bxD4cH1iyeglh5KcBw",
            "version": "1.33.1"
        },
        "server_id": {
            "host": "0.0.0.0",
            "id": "NCLH2BAHSW2ASMRX7IIVUPQRUDTC556SMEY5L7PWNHZUJYQ7UDV7C7BA",
            "name": "NCLH2BAHSW2ASMRX7IIVUPQRUDTC556SMEY5L7PWNHZUJYQ7UDV7C7BA",
            "version": "2.10.18",
            "xkey": "XAVESR4X4YVIJJ7VHJWAIQYRU7TMIZCYD36HYSYBYWJWB5GKHDFHETUU"
        },
        "type": "authorization_request",
        "user_nkey": "UCN6UGLQZQB5GXHQOQOSMXYKN4PRMB7PSXVVEDIAWAFNBO25NOUK6DCU",
        "version": 2
    },
    "sub": "ACVUKSAVDJV65AZLNRPSKFJPY22WNRZIXFUORXXKVY2LHXM2JMKL7G4F"
}"#;

        let auth: Claims<AuthRequest> = serde_json::from_str(token).unwrap();
        assert_ne!(auth.payload().client_info.user, "");
    }
}
