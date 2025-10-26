//! Rust helper library for the ICP stealth announcement protocol.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use alloy_primitives::{Signature as AlloySignature, B256};
use bls12_381::{G2Affine, G2Projective, Scalar};
use candid::{Decode, Encode, Principal};
use hkdf::Hkdf;
use ic_agent::{Agent, AgentError};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use std::convert::TryInto;

pub mod config {
    /// Default HKDF salt for deriving symmetric keys.
    pub const HKDF_SALT: &[u8] = b"icp-stealth";
    /// HKDF info label for the AES-256-GCM encryption key.
    pub const HKDF_INFO_ENC: &[u8] = b"aes-gcm-256";
    /// HKDF info label for the one-byte view tag extraction.
    pub const HKDF_INFO_TAG: &[u8] = b"view-tag";
    /// Domain separator used when deriving the viewing secret scalar from a vetKey.
    pub const VIEW_KEY_DOMAIN: &str = "icp-stealth-view-sk";
    /// Scheme identifier appended to the EVM address when deriving VetKD inputs.
    pub const SCHEME_ID: &[u8] = b"icp-stealth-bls-g2-v1";
}

pub mod types {
    use super::*;
    use candid::CandidType;

    #[derive(Clone, Debug, Serialize, Deserialize, CandidType)]
    pub struct AnnouncementInput {
        pub view_tag: u8,
        pub ephemeral_public_key: Vec<u8>,
        pub ciphertext: Vec<u8>,
        pub nonce: Vec<u8>,
        pub payload_type: Option<String>,
        pub metadata: Option<Vec<u8>>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, CandidType)]
    pub struct Announcement {
        pub id: u64,
        pub view_tag: u8,
        pub ephemeral_public_key: Vec<u8>,
        pub ciphertext: Vec<u8>,
        pub nonce: Vec<u8>,
        pub payload_type: Option<String>,
        pub metadata: Option<Vec<u8>>,
        pub created_at_ns: u64,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, CandidType)]
    pub struct AnnouncementPage {
        pub announcements: Vec<Announcement>,
        pub next_id: Option<u64>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, CandidType)]
    pub struct DecryptedAnnouncement {
        pub id: u64,
        pub plaintext: Vec<u8>,
        pub metadata: Option<Vec<u8>>,
        pub created_at_ns: u64,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, CandidType)]
    pub struct EncryptedViewKeyRequest {
        pub address: Vec<u8>,
        pub transport_public_key: Vec<u8>,
        pub expiry_ns: u64,
        pub nonce: u64,
        pub signature: Vec<u8>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, CandidType)]
    pub struct EncryptedViewKeyResponse {
        pub encrypted_key: Vec<u8>,
        pub view_public_key: Vec<u8>,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StealthError {
    #[error("invalid address length: expected 20 bytes")]
    InvalidAddress,
    #[error("invalid G2 encoding")]
    InvalidG2Encoding,
    #[error("encryption failure")]
    EncryptionFailed,
    #[error("decryption failure")]
    DecryptionFailed,
    #[error("HKDF expansion failed")]
    Hkdf,
    #[error("scalar conversion failed")]
    InvalidScalar,
    #[error("transport key error: {0}")]
    Transport(String),
}

pub type Result<T> = std::result::Result<T, StealthError>;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("agent error: {0}")]
    Agent(#[from] AgentError),
    #[error("candid error: {0}")]
    Candid(#[from] candid::Error),
    #[error("canister error: {0}")]
    Canister(String),
}

pub type ClientResult<T> = std::result::Result<T, ClientError>;

pub struct StealthCanisterClient {
    agent: Agent,
    storage_canister_id: Principal,
    key_manager_canister_id: Principal,
}

impl StealthCanisterClient {
    pub fn new(
        agent: Agent,
        storage_canister_id: Principal,
        key_manager_canister_id: Principal,
    ) -> Self {
        Self {
            agent,
            storage_canister_id,
            key_manager_canister_id,
        }
    }

    pub fn agent(&self) -> &Agent {
        &self.agent
    }

    pub fn storage_canister_id(&self) -> Principal {
        self.storage_canister_id
    }

    pub fn key_manager_canister_id(&self) -> Principal {
        self.key_manager_canister_id
    }

    pub async fn get_view_public_key(&self, address: [u8; 20]) -> ClientResult<Vec<u8>> {
        let arg = candid::Encode!(&address.to_vec())?;
        let response = self
            .agent
            .update(&self.key_manager_canister_id, "get_view_public_key")
            .with_arg(arg)
            .call_and_wait()
            .await?;
        let result: std::result::Result<Vec<u8>, String> =
            candid::Decode!(&response, std::result::Result<Vec<u8>, String>)?;
        result.map_err(ClientError::Canister)
    }

    pub async fn request_encrypted_view_key(
        &self,
        request: &types::EncryptedViewKeyRequest,
    ) -> ClientResult<Vec<u8>> {
        let arg = candid::Encode!(request)?;
        let response = self
            .agent
            .update(&self.key_manager_canister_id, "request_encrypted_view_key")
            .with_arg(arg)
            .call_and_wait()
            .await?;
        let result: std::result::Result<Vec<u8>, String> =
            candid::Decode!(&response, std::result::Result<Vec<u8>, String>)?;
        result.map_err(ClientError::Canister)
    }

    pub async fn submit_announcement(
        &self,
        input: &types::AnnouncementInput,
    ) -> ClientResult<types::Announcement> {
        let arg = candid::Encode!(input)?;
        let response = self
            .agent
            .update(&self.storage_canister_id, "submit_announcement")
            .with_arg(arg)
            .call_and_wait()
            .await?;
        let (announcement,) = candid::Decode!(&response, (types::Announcement,))?;
        Ok(announcement)
    }

    pub async fn list_announcements(
        &self,
        start_after: Option<u64>,
        limit: Option<u32>,
    ) -> ClientResult<types::AnnouncementPage> {
        let arg = candid::Encode!(&start_after, &limit)?;
        let response = self
            .agent
            .query(&self.storage_canister_id, "list_announcements")
            .with_arg(arg)
            .call()
            .await?;
        let (page,) = candid::Decode!(&response, (types::AnnouncementPage,))?;
        Ok(page)
    }

    pub async fn get_announcement(&self, id: u64) -> ClientResult<Option<types::Announcement>> {
        let arg = candid::Encode!(&id)?;
        let response = self
            .agent
            .query(&self.storage_canister_id, "get_announcement")
            .with_arg(arg)
            .call()
            .await?;
        let (announcement,) = candid::Decode!(&response, (Option<types::Announcement>,))?;
        Ok(announcement)
    }
}

pub struct EphemeralKeyPair {
    pub secret: [u8; 32],
    pub public: [u8; 96],
}

pub struct EncryptionResult {
    pub announcement: types::AnnouncementInput,
    pub ephemeral_secret: [u8; 32],
    pub view_tag_key: [u8; 32],
}

pub fn generate_ephemeral_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> EphemeralKeyPair {
    loop {
        let mut candidate = [0u8; 32];
        rng.fill_bytes(&mut candidate);
        let scalar = Scalar::from_bytes(&candidate).into_option();
        if let Some(scalar) = scalar {
            if scalar == Scalar::zero() {
                continue;
            }
            let public = G2Affine::from(G2Projective::generator() * scalar).to_compressed();
            return EphemeralKeyPair {
                secret: scalar.to_bytes(),
                public,
            };
        }
    }
}

pub fn encrypt_payload<R: RngCore + CryptoRng>(
    rng: &mut R,
    _address: [u8; 20],
    view_public_key_bytes: &[u8],
    plaintext: &[u8],
    payload_type: Option<String>,
    metadata: Option<Vec<u8>>,
    nonce_override: Option<[u8; 12]>,
) -> Result<EncryptionResult> {
    let view_public = decompress_g2(view_public_key_bytes)?;
    let ephemeral = generate_ephemeral_keypair(rng);
    let secret_scalar = Scalar::from_bytes(&ephemeral.secret)
        .into_option()
        .ok_or(StealthError::InvalidScalar)?;
    let shared_projective = G2Projective::from(view_public) * secret_scalar;
    let shared_bytes = G2Affine::from(shared_projective).to_compressed();
    let hk = Hkdf::<Sha256>::new(Some(config::HKDF_SALT), &shared_bytes);

    let mut aes_key = [0u8; 32];
    hk.expand(config::HKDF_INFO_ENC, &mut aes_key)
        .map_err(|_| StealthError::Hkdf)?;
    let mut tag_key = [0u8; 32];
    hk.expand(config::HKDF_INFO_TAG, &mut tag_key)
        .map_err(|_| StealthError::Hkdf)?;

    let nonce_bytes = match nonce_override {
        Some(nonce) => nonce,
        None => {
            let mut nonce = [0u8; 12];
            rng.fill_bytes(&mut nonce);
            nonce
        }
    };

    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|_| StealthError::EncryptionFailed)?;
    let nonce_ga = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce_ga, plaintext)
        .map_err(|_| StealthError::EncryptionFailed)?;
    let nonce_vec = {
        let array: [u8; 12] = nonce_ga.into();
        array.to_vec()
    };

    let announcement = types::AnnouncementInput {
        view_tag: tag_key[0],
        ephemeral_public_key: Vec::from(ephemeral.public),
        ciphertext,
        nonce: nonce_vec,
        payload_type,
        metadata,
    };

    Ok(EncryptionResult {
        announcement,
        ephemeral_secret: ephemeral.secret,
        view_tag_key: tag_key,
    })
}

pub fn decrypt_announcement(
    view_secret: &[u8; 32],
    announcement: &types::Announcement,
) -> Result<Option<types::DecryptedAnnouncement>> {
    let view_scalar = Scalar::from_bytes(view_secret)
        .into_option()
        .ok_or(StealthError::InvalidScalar)?;
    let ephemeral = decompress_g2(&announcement.ephemeral_public_key)?;
    let shared_projective = G2Projective::from(ephemeral) * view_scalar;
    let shared_bytes = G2Affine::from(shared_projective).to_compressed();
    let hk = Hkdf::<Sha256>::new(Some(config::HKDF_SALT), &shared_bytes);

    let mut tag_key = [0u8; 32];
    hk.expand(config::HKDF_INFO_TAG, &mut tag_key)
        .map_err(|_| StealthError::Hkdf)?;
    if tag_key[0] != announcement.view_tag {
        return Ok(None);
    }

    let mut aes_key = [0u8; 32];
    hk.expand(config::HKDF_INFO_ENC, &mut aes_key)
        .map_err(|_| StealthError::Hkdf)?;
    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|_| StealthError::DecryptionFailed)?;
    let nonce_arr: [u8; 12] = announcement
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| StealthError::DecryptionFailed)?;
    let nonce_ga = Nonce::from(nonce_arr);
    let plaintext = cipher
        .decrypt(&nonce_ga, announcement.ciphertext.as_ref())
        .map_err(|_| StealthError::DecryptionFailed)?;

    Ok(Some(types::DecryptedAnnouncement {
        id: announcement.id,
        plaintext,
        metadata: announcement.metadata.clone(),
        created_at_ns: announcement.created_at_ns,
    }))
}

pub fn scan_announcements(
    view_secret: &[u8; 32],
    announcements: &[types::Announcement],
) -> Result<Vec<types::DecryptedAnnouncement>> {
    let mut decrypted = Vec::new();
    for announcement in announcements {
        if let Some(message) = decrypt_announcement(view_secret, announcement)? {
            decrypted.push(message);
        }
    }
    Ok(decrypted)
}

pub mod recipient {
    use super::*;
    use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey, TransportSecretKey};

    pub struct TransportKeyPair {
        pub secret: TransportSecretKey,
        pub public: Vec<u8>,
    }

    pub fn prepare_transport_key() -> TransportKeyPair {
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let secret =
            TransportSecretKey::from_seed(seed.to_vec()).expect("seed length is fixed to 32 bytes");
        let public = secret.public_key();
        TransportKeyPair { secret, public }
    }

    pub fn decrypt_vet_key(
        address: [u8; 20],
        scheme_id: &[u8],
        encrypted_key: &[u8],
        derived_public_key: &[u8],
        transport_secret: &TransportSecretKey,
    ) -> Result<[u8; 32]> {
        let encrypted =
            EncryptedVetKey::deserialize(encrypted_key).map_err(|e| StealthError::Transport(e))?;
        let derived = DerivedPublicKey::deserialize(derived_public_key)
            .map_err(|_| StealthError::Transport("invalid derived public key".into()))?;
        let mut input = Vec::with_capacity(address.len() + scheme_id.len());
        input.extend_from_slice(&address);
        input.extend_from_slice(scheme_id);
        let vet_key = encrypted
            .decrypt_and_verify(transport_secret, &derived, &input)
            .map_err(|e| StealthError::Transport(e))?;
        let material = vet_key.derive_symmetric_key(config::VIEW_KEY_DOMAIN, 32);
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&material);
        let scalar = Scalar::from_bytes(&scalar_bytes)
            .into_option()
            .ok_or(StealthError::InvalidScalar)?;
        let expected = G2Affine::from(G2Projective::generator() * scalar).to_compressed();
        if expected.as_ref() != derived_public_key {
            return Err(StealthError::Transport("mismatched viewing key".into()));
        }
        Ok(scalar.to_bytes())
    }
}

pub mod sender {
    use super::*;

    pub fn build_authorization_message(
        canister: Principal,
        address: [u8; 20],
        transport_public_key: &[u8],
        expiry_ns: u64,
        nonce: u64,
    ) -> Vec<u8> {
        let body = format!(
            "ICP Stealth Authorization:\naddress: 0x{}\ncanister: {}\ntransport: 0x{}\nexpiry_ns:{expiry_ns}\nnonce:{nonce}",
            hex::encode(address),
            canister.to_text(),
            hex::encode(transport_public_key),
        );
        let prefix = format!("\x19Ethereum Signed Message:\n{}", body.len());
        [prefix.as_bytes(), body.as_bytes()].concat()
    }

    pub fn recover_address(message: &[u8], signature: &[u8]) -> Result<[u8; 20]> {
        if signature.len() != 65 {
            return Err(StealthError::Transport("signature length".into()));
        }
        let signature = AlloySignature::from_raw(signature)
            .map_err(|_| StealthError::Transport("invalid signature".into()))?;
        let digest = Keccak256::digest(message);
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&digest);
        let hash = B256::from(hash_bytes);
        let address = signature
            .recover_address_from_prehash(&hash)
            .map_err(|_| StealthError::Transport("recovery failed".into()))?;
        Ok(address.into_array())
    }
}

fn decompress_g2(bytes: &[u8]) -> Result<G2Affine> {
    if bytes.len() != 96 {
        return Err(StealthError::InvalidG2Encoding);
    }
    let mut array = [0u8; 96];
    array.copy_from_slice(bytes);
    G2Affine::from_compressed(&array)
        .into_option()
        .ok_or(StealthError::InvalidG2Encoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_key_generation() {
        let mut rng = OsRng;
        let pair = generate_ephemeral_keypair(&mut rng);
        assert_eq!(pair.public.len(), 96);
    }
}
