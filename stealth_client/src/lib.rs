//! Rust helper library for the ICP stealth announcement protocol.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use alloy_primitives::{Signature as AlloySignature, B256};
use candid::{Decode, Encode, Principal};
use ic_agent::{Agent, AgentError};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::convert::TryInto;

use ic_vetkeys::{DerivedPublicKey, IbeCiphertext, IbeIdentity, IbeSeed, VetKey};

pub mod types {
    use super::*;
    use candid::CandidType;

    #[derive(Clone, Debug, Serialize, Deserialize, CandidType)]
    pub struct AnnouncementInput {
        pub ibe_ciphertext: Vec<u8>,
        pub ciphertext: Vec<u8>,
        pub nonce: Vec<u8>,
    }

    #[derive(Clone, Debug, Serialize, Deserialize, CandidType)]
    pub struct Announcement {
        pub id: u64,
        pub ibe_ciphertext: Vec<u8>,
        pub ciphertext: Vec<u8>,
        pub nonce: Vec<u8>,
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
    #[error("invalid derived public key")]
    InvalidDerivedPublicKey,
    #[error("encryption failure")]
    EncryptionFailed,
    #[error("decryption failure")]
    DecryptionFailed,
    #[error("IBE encryption failed: {0}")]
    IbeEncryption(String),
    #[error("IBE decryption failed: {0}")]
    IbeDecryption(String),
    #[error("invalid nonce length")]
    InvalidNonce,
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
        let result: std::result::Result<types::Announcement, String> =
            candid::Decode!(&response, std::result::Result<types::Announcement, String>)?;
        result.map_err(ClientError::Canister)
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
        let page = candid::Decode!(&response, types::AnnouncementPage)?;
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

pub struct EncryptionResult {
    pub announcement: types::AnnouncementInput,
}

pub fn encrypt_payload<R: RngCore + CryptoRng>(
    rng: &mut R,
    view_public_key_bytes: &[u8],
    address: [u8; 20],
    plaintext: &[u8],
    nonce_override: Option<[u8; 12]>,
) -> Result<EncryptionResult> {
    let derived_public_key = DerivedPublicKey::deserialize(view_public_key_bytes)
        .map_err(|_| StealthError::InvalidDerivedPublicKey)?;
    let identity = IbeIdentity::from_bytes(&address);
    let seed = IbeSeed::random(rng);

    let mut aes_key = [0u8; 32];
    rng.fill_bytes(&mut aes_key);

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

    let ibe_ciphertext =
        IbeCiphertext::encrypt(&derived_public_key, &identity, &aes_key, &seed).serialize();

    aes_key.fill(0);

    let announcement = types::AnnouncementInput {
        ibe_ciphertext,
        ciphertext,
        nonce: nonce_vec,
    };

    Ok(EncryptionResult { announcement })
}

pub fn decrypt_announcement(
    vet_key: &VetKey,
    announcement: &types::Announcement,
) -> Result<Option<types::DecryptedAnnouncement>> {
    if announcement.ibe_ciphertext.is_empty() {
        return Ok(None);
    }

    let ibe_ciphertext = IbeCiphertext::deserialize(&announcement.ibe_ciphertext)
        .map_err(StealthError::IbeDecryption)?;
    let mut session_key = match ibe_ciphertext.decrypt(vet_key) {
        Ok(key) => key,
        Err(_err) => return Ok(None),
    };
    if session_key.len() != 32 {
        return Err(StealthError::IbeDecryption(
            "unexpected session key length".to_string(),
        ));
    }

    let cipher =
        Aes256Gcm::new_from_slice(&session_key).map_err(|_| StealthError::DecryptionFailed)?;
    let nonce_arr: [u8; 12] = announcement
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| StealthError::InvalidNonce)?;
    let nonce_ga = Nonce::from(nonce_arr);
    let plaintext = cipher
        .decrypt(&nonce_ga, announcement.ciphertext.as_ref())
        .map_err(|_| StealthError::DecryptionFailed)?;

    session_key.iter_mut().for_each(|b| *b = 0);

    Ok(Some(types::DecryptedAnnouncement {
        id: announcement.id,
        plaintext,
        created_at_ns: announcement.created_at_ns,
    }))
}

pub fn scan_announcements(
    vet_key: &VetKey,
    announcements: &[types::Announcement],
) -> Result<Vec<types::DecryptedAnnouncement>> {
    let mut decrypted = Vec::new();
    for announcement in announcements {
        if let Some(message) = decrypt_announcement(vet_key, announcement)? {
            decrypted.push(message);
        }
    }
    Ok(decrypted)
}

pub mod recipient {
    use super::*;
    use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey, TransportSecretKey, VetKey};

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
        encrypted_key: &[u8],
        derived_public_key: &[u8],
        transport_secret: &TransportSecretKey,
    ) -> Result<VetKey> {
        let encrypted =
            EncryptedVetKey::deserialize(encrypted_key).map_err(|e| StealthError::Transport(e))?;
        let derived = DerivedPublicKey::deserialize(derived_public_key)
            .map_err(|_| StealthError::Transport("invalid derived public key".into()))?;
        let vet_key = encrypted
            .decrypt_and_verify(transport_secret, &derived, &[])
            .map_err(|e| StealthError::Transport(e))?;
        Ok(vet_key)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_rejects_invalid_public_key() {
        let mut rng = OsRng;
        let view_public_key = vec![0u8; 95];
        let result = encrypt_payload(&mut rng, &view_public_key, [0u8; 20], b"hello", None);
        assert!(matches!(result, Err(StealthError::InvalidDerivedPublicKey)));
    }
}
