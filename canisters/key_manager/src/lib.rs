use std::cell::RefCell;
use std::collections::BTreeMap;
use std::convert::TryFrom;

use alloy_primitives::{Signature as AlloySignature, B256};
use candid::Principal;
use candid::{CandidType, Deserialize};
use ic_cdk::api::{canister_self, time};
use ic_cdk::management_canister::{
    vetkd_derive_key, vetkd_public_key, VetKDCurve, VetKDDeriveKeyArgs, VetKDKeyId,
    VetKDPublicKeyArgs,
};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, update};
use sha3::{Digest, Keccak256};

const CONTEXT_BASE: &[u8] = b"icp-stealth-announcement-v1";

type Address = [u8; 20];
type Result<T> = std::result::Result<T, String>;

#[derive(Clone, CandidType, Deserialize)]
pub struct InitArgs {
    pub key_id_name: String,
}

#[derive(Clone, CandidType, Deserialize)]
struct Config {
    key_id_name: String,
}

#[derive(Clone, CandidType, Deserialize)]
struct State {
    config: Config,
    max_nonce_by_address: BTreeMap<Address, u64>,
}

thread_local! {
    static STATE: RefCell<Option<State>> = RefCell::new(None);
}

#[derive(CandidType, Deserialize)]
pub struct EncryptedViewKeyRequest {
    pub address: Vec<u8>,
    pub transport_public_key: Vec<u8>,
    pub expiry_ns: u64,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

#[init]
fn init(args: InitArgs) {
    let key_id_name = args.key_id_name;
    let config = Config { key_id_name };

    STATE.with(|state| {
        *state.borrow_mut() = Some(State {
            config,
            max_nonce_by_address: BTreeMap::new(),
        })
    });
}

#[pre_upgrade]
fn pre_upgrade() {
    let state = STATE.with(|state| state.borrow().clone());
    ic_cdk::storage::stable_save((state,)).expect("failed to persist state");
}

#[post_upgrade]
fn post_upgrade() {
    let (maybe_state,): (Option<State>,) =
        ic_cdk::storage::stable_restore().expect("failed to restore state");
    STATE.with(|state| {
        *state.borrow_mut() = maybe_state;
    });
}

#[update]
async fn get_view_public_key(address: Vec<u8>) -> Result<Vec<u8>> {
    let address = to_address(&address)?;
    let config = with_state(|state| state.config.clone())?;
    let args = VetKDPublicKeyArgs {
        canister_id: None,
        context: context_for_address(&address),
        key_id: VetKDKeyId {
            curve: VetKDCurve::Bls12_381_G2,
            name: config.key_id_name.clone(),
        },
    };

    let reply = vetkd_public_key(&args)
        .await
        .map_err(|err| err.to_string())?;
    Ok(reply.public_key)
}

#[update]
async fn request_encrypted_view_key(request: EncryptedViewKeyRequest) -> Result<Vec<u8>> {
    let address = to_address(&request.address)?;
    let config = with_state(|state| state.config.clone())?;
    let now = time();
    if request.expiry_ns < now {
        return Err("authorization expired".to_string());
    }

    STATE.with(|state| -> Result<()> {
        let mut state = state.borrow_mut();
        let state = state
            .as_mut()
            .ok_or_else(|| "key manager not initialized".to_string())?;
        let entry = state.max_nonce_by_address.entry(address).or_default();
        if request.nonce <= *entry {
            return Err("nonce reuse detected".to_string());
        }
        *entry = request.nonce;
        Ok(())
    })?;

    let message = auth_message(
        canister_self(),
        &address,
        &request.transport_public_key,
        request.expiry_ns,
        request.nonce,
    );
    let recovered = recover_address(&message, &request.signature)?;
    if recovered != address {
        return Err("signature does not match address".to_string());
    }

    let args = VetKDDeriveKeyArgs {
        context: context_for_address(&address),
        input: Vec::new(),
        key_id: VetKDKeyId {
            curve: VetKDCurve::Bls12_381_G2,
            name: config.key_id_name.clone(),
        },
        transport_public_key: request.transport_public_key.clone(),
    };

    let reply = vetkd_derive_key(&args)
        .await
        .map_err(|err| err.to_string())?;

    Ok(reply.encrypted_key)
}

fn with_state<F, R>(f: F) -> Result<R>
where
    F: FnOnce(&State) -> R,
{
    STATE.with(|state| {
        state
            .borrow()
            .as_ref()
            .map(f)
            .ok_or_else(|| "key manager not initialized".to_string())
    })
}

fn to_address(bytes: &[u8]) -> Result<Address> {
    <[u8; 20]>::try_from(bytes).map_err(|_| "address must be 20 bytes".to_string())
}

fn context_for_address(address: &Address) -> Vec<u8> {
    let mut context = CONTEXT_BASE.to_vec();
    context.extend_from_slice(address);
    context
}

fn auth_message(
    canister_id: Principal,
    address: &Address,
    transport_public_key: &[u8],
    expiry_ns: u64,
    nonce: u64,
) -> Vec<u8> {
    let body = format!(
        "ICP Stealth Authorization:\naddress: 0x{}\ncanister: {}\ntransport: 0x{}\nexpiry_ns:{expiry_ns}\nnonce:{nonce}",
        hex::encode(address),
        canister_id.to_text(),
        hex::encode(transport_public_key),
    );
    let prefix = format!("\x19Ethereum Signed Message:\n{}", body.len());
    [prefix.into_bytes(), body.into_bytes()].concat()
}

fn recover_address(message: &[u8], signature: &[u8]) -> Result<Address> {
    if signature.len() != 65 {
        return Err("signature must be 65 bytes (r||s||v)".to_string());
    }
    let signature =
        AlloySignature::from_raw(signature).map_err(|_| "invalid signature".to_string())?;
    let digest = Keccak256::digest(message);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&digest);
    let hash = B256::from(hash_bytes);
    let address = signature
        .recover_address_from_prehash(&hash)
        .map_err(|_| "failed to recover signer".to_string())?;
    Ok(address.into_array())
}

ic_cdk::export_candid!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_message_format() {
        let address = [0u8; 20];
        let msg = auth_message(
            Principal::management_canister(),
            &address,
            &[1, 2, 3],
            42,
            7,
        );
        assert!(msg.starts_with(b"\x19Ethereum Signed Message:\n"));
    }
}
