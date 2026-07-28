use std::str;
use std::sync::Arc;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair};
use serde::Serialize;

use crate::errors::CbError;
use crate::time;
use crate::types::CbResult;

#[derive(Serialize)]
struct Header<'a> {
    alg: &'a str,
    kid: String,
    nonce: String,
}

#[derive(Serialize)]
struct Payload<'a> {
    sub: String,
    iss: &'a str,
    nbf: u64,
    exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
}

#[derive(Debug)]
pub(crate) struct Jwt {
    /// API Key provided by the service.
    api_key: String,
    /// Pre-initialized Ed25519 signing key pair.
    signing_key: Arc<Ed25519KeyPair>,
    /// RNG for signing.
    rng: SystemRandom,
}

impl Clone for Jwt {
    fn clone(&self) -> Self {
        Self {
            api_key: self.api_key.clone(),
            signing_key: Arc::clone(&self.signing_key),
            rng: SystemRandom::new(),
        }
    }
}

impl Jwt {
    /// Create a new instance of the JSON Web Token (Jwt) used to generate new tokens.
    pub(crate) fn new(api_key: &str, api_secret: &str) -> CbResult<Self> {

        // Initialize SystemRandom.
        let rng = SystemRandom::new();

        // Initialize the Ed25519KeyPair once.
        let signing_key_bytes = STANDARD.decode(api_secret)
                .map_err(|why| CbError::BadSignature(why.to_string()))?;

        let (seed, public_key) = signing_key_bytes.split_at(32);
        let signing_key = Ed25519KeyPair::from_seed_and_public_key(seed, public_key)
                .map_err(|why| CbError::BadSignature(why.to_string()))?;

        Ok(Self {
            api_key: api_key.to_string(),
            signing_key: Arc::new(signing_key),
            rng,
        })
    }

    #[inline]
    pub(crate) fn build_uri(method: &str, root: &str, url: &str) -> String {
        format!("{method} {root}{url}")
    }

    /// Creates the header for the message.
    fn build_header(&self) -> CbResult<Header<'static>> {
        // Generate 48 random bytes for the nonce (resulting in 64 Base64 characters)
        let mut nonce_bytes = [0u8; 48];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|why| CbError::BadSignature(format!("RNG error: {why:?}")))?;

        Ok(Header {
            alg: "ES256",
            kid: self.api_key.clone(),
            nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
        })
    }

    /// Creates the payload for the message.
    fn build_payload(&self, uri: Option<&str>) -> Payload<'static> {
        let now = time::now();
        Payload {
            sub: self.api_key.clone(),
            iss: "coinbase-cloud",
            nbf: now,
            exp: now + 120,
            uri: uri.map(String::from),
        }
    }

    /// Encodes (base64) a raw byte slice (`&[u8]`).
    #[inline]
    fn to_base64(input: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(input)
    }

    /// Encodes a serializable type.
    fn base64_encode<T: Serialize>(input: &T) -> CbResult<String> {
        let raw =
            serde_json::to_vec(input).map_err(|why| CbError::BadSignature(why.to_string()))?;
        Ok(Self::to_base64(&raw))
    }

    /// Signs a message using the pre-initialized Ed25519 key pair.
    ///
    /// # Arguments
    ///
    /// * `message`: A byte slice (`&[u8]`) of the message to be signed.
    ///
    /// # Returns
    ///
    /// A `CbResult<String>` with the base64-encoded signature if successful; otherwise, an error.
    fn sign_message(&self, message: &[u8]) -> CbResult<String> {
        let signature = self
            .signing_key
            .sign(message);
        Ok(Self::to_base64(signature.as_ref()))
    }

    /// Encodes JWT headers and payload into a signed JWT token.
    ///
    /// # Arguments
    ///
    /// * `uri`: the URI being accessed.
    ///
    /// # Returns
    ///
    /// A `CbResult<String>` with the JWT token if successful; otherwise, an error.
    pub(crate) fn encode(&self, uri: Option<&str>) -> CbResult<String> {
        // Convert the header and payload into base64.
        let header = self.build_header()?.serialize_base64()?;
        let payload = Jwt::base64_encode(&self.build_payload(uri))?;

        // Estimate capacity: header + payload + signature + 2 dots
        // Assuming signature is ~86 characters for Ed25519
        let mut message = String::with_capacity(header.len() + payload.len() + 88);
        message.push_str(&header);
        message.push('.');
        message.push_str(&payload);

        // Sign the message.
        let signature = self.sign_message(message.as_bytes())?;
        message.push('.');
        message.push_str(&signature);

        Ok(message)
    }
}

// Implement serialization for Header to handle base64 encoding
impl Header<'_> {
    fn serialize_base64(&self) -> CbResult<String> {
        let raw = serde_json::to_vec(self).map_err(|why| CbError::BadSignature(why.to_string()))?;
        Ok(URL_SAFE_NO_PAD.encode(&raw))
    }
}
