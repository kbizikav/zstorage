use std::convert::TryInto;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::{CryptoRng, RngCore};

use crate::{types, Result, StealthError};
use ic_vetkeys::{DerivedPublicKey, IbeCiphertext, IbeIdentity, IbeSeed, VetKey};

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

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn encrypt_rejects_invalid_public_key() {
        let mut rng = OsRng;
        let view_public_key = vec![0u8; 95];
        let result = encrypt_payload(&mut rng, &view_public_key, [0u8; 20], b"hello", None);
        assert!(matches!(result, Err(StealthError::InvalidDerivedPublicKey)));
    }
}
