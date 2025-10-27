use alloy_primitives::{Signature as AlloySignature, B256};
use candid::Principal;
use sha3::{Digest, Keccak256};

use crate::{Result, StealthError};

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
