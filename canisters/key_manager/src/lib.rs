use std::cell::RefCell;
use std::collections::BTreeMap;
use std::convert::TryFrom;

use bls12_381::{G2Affine, G2Projective, Scalar};
use candid::Principal;
use candid::{CandidType, Deserialize};
use hkdf::Hkdf;
use ic_cdk::api::{canister_self, msg_caller, time};
use ic_cdk::call::Call;
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha2::Sha256;
use sha3::{Digest, Keccak256};

const CONTEXT_DEFAULT: &[u8] = b"icp-stealth-announcement-v1";
const SCHEME_ID_DEFAULT: &[u8] = b"icp-stealth-bls-g2-v1";

type Address = [u8; 20];

#[derive(Clone, CandidType, Deserialize)]
pub struct InitArgs {
    pub master_public_key: Vec<u8>,
    #[serde(default)]
    pub key_id_name: Option<String>,
    #[serde(default)]
    pub context: Option<Vec<u8>>,
    #[serde(default)]
    pub scheme_id: Option<Vec<u8>>,
}

#[derive(Clone, CandidType, Deserialize)]
struct Config {
    context: Vec<u8>,
    scheme_id: Vec<u8>,
    key_id_name: String,
    master_public_key: Vec<u8>,
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
pub struct ViewPublicKeyRequest {
    pub address: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
pub struct ViewPublicKeyResponse {
    pub public_key: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
pub struct EncryptedViewKeyRequest {
    pub address: Vec<u8>,
    pub transport_public_key: Vec<u8>,
    pub expiry_ns: u64,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
pub struct EncryptedViewKeyResponse {
    pub encrypted_key: Vec<u8>,
    pub view_public_key: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
struct VetKDKeyId {
    curve: VetKDCurve,
    name: String,
}

#[derive(CandidType, Deserialize, Clone, Copy)]
enum VetKDCurve {
    #[serde(rename = "bls12_381_g2")]
    Bls12_381G2,
}

#[derive(CandidType, Deserialize)]
struct VetKDDeriveKeyArgs {
    context: Vec<u8>,
    input: Vec<u8>,
    key_id: VetKDKeyId,
    transport_public_key: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
struct VetKDEncryptedKey {
    encrypted_key: Vec<u8>,
}

#[init]
fn init(args: InitArgs) {
    let key_id_name = args.key_id_name.unwrap_or_else(|| "test_key_1".to_string());
    let config = Config {
        context: args.context.unwrap_or_else(|| CONTEXT_DEFAULT.to_vec()),
        scheme_id: args.scheme_id.unwrap_or_else(|| SCHEME_ID_DEFAULT.to_vec()),
        key_id_name,
        master_public_key: args.master_public_key,
    };

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

#[query]
fn get_view_public_key(request: ViewPublicKeyRequest) -> Result<ViewPublicKeyResponse, String> {
    let address = to_address(&request.address)?;
    let config = with_state(|state| state.config.clone())?;
    let derived = derive_view_public_key(&config, address)?;
    Ok(ViewPublicKeyResponse {
        public_key: derived,
    })
}

#[update]
async fn request_encrypted_view_key(
    request: EncryptedViewKeyRequest,
) -> Result<EncryptedViewKeyResponse, String> {
    let address = to_address(&request.address)?;
    let config = with_state(|state| state.config.clone())?;
    let now = time();
    if request.expiry_ns < now {
        return Err("authorization expired".to_string());
    }

    STATE.with(|state| -> Result<(), String> {
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

    let message = authorization_message(
        &address,
        &request.transport_public_key,
        request.expiry_ns,
        request.nonce,
    );
    let recovered = recover_address(&message, &request.signature)?;
    if recovered != address {
        return Err("signature does not match address".to_string());
    }

    let view_public_key = derive_view_public_key(&config, address)?;
    let mut input = Vec::with_capacity(address.len() + config.scheme_id.len());
    input.extend_from_slice(&address);
    input.extend_from_slice(&config.scheme_id);

    let args = VetKDDeriveKeyArgs {
        context: derive_context(&config.context, msg_caller()),
        input,
        key_id: VetKDKeyId {
            curve: VetKDCurve::Bls12_381G2,
            name: config.key_id_name.clone(),
        },
        transport_public_key: request.transport_public_key.clone(),
    };

    let response = Call::unbounded_wait(Principal::management_canister(), "vetkd_derive_key")
        .with_arg((args,))
        .await
        .map_err(|err| err.to_string())?;
    let (encrypted,): (VetKDEncryptedKey,) = response
        .candid_tuple()
        .map_err(|err| err.to_string())?;

    Ok(EncryptedViewKeyResponse {
        encrypted_key: encrypted.encrypted_key,
        view_public_key,
    })
}

fn with_state<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce(&State) -> R,
{
    STATE.with(|state| {
        let state = state.borrow();
        let state = state
            .as_ref()
            .ok_or_else(|| "key manager not initialized".to_string())?;
        Ok(f(state))
    })
}

fn to_address(bytes: &[u8]) -> Result<Address, String> {
    if bytes.len() != 20 {
        return Err("address must be 20 bytes".to_string());
    }
    let mut address = [0u8; 20];
    address.copy_from_slice(bytes);
    Ok(address)
}

fn derive_view_public_key(config: &Config, address: Address) -> Result<Vec<u8>, String> {
    let g: G2Projective = bls12_381::G2Projective::generator();
    let scalar = derive_scalar(config, address)?;
    let point = g * scalar;
    let affine = G2Affine::from(point);
    Ok(affine.to_compressed().to_vec())
}

fn derive_scalar(config: &Config, address: Address) -> Result<Scalar, String> {
    let mut hkdf_input = Vec::new();
    hkdf_input.extend_from_slice(&config.context);
    hkdf_input.extend_from_slice(canister_self().as_slice());
    hkdf_input.extend_from_slice(&address);
    hkdf_input.extend_from_slice(&config.scheme_id);
    hkdf_input.extend_from_slice(&config.master_public_key);

    let hk = Hkdf::<Sha256>::new(Some(&config.context), &hkdf_input);
    let mut okm = [0u8; 64];
    hk.expand(&config.scheme_id, &mut okm)
        .map_err(|_| "hkdf expand failed".to_string())?;
    Ok(Scalar::from_bytes_wide(&okm))
}

fn derive_context(base: &[u8], caller: Principal) -> Vec<u8> {
    let mut context = Vec::with_capacity(base.len() + caller.as_slice().len());
    context.extend_from_slice(base);
    context.extend_from_slice(caller.as_slice());
    context
}

fn authorization_message(
    address: &Address,
    transport_public_key: &[u8],
    expiry_ns: u64,
    nonce: u64,
) -> Vec<u8> {
    authorization_message_with_canister(
        canister_self(),
        address,
        transport_public_key,
        expiry_ns,
        nonce,
    )
}

fn authorization_message_with_canister(
    canister_id: Principal,
    address: &Address,
    transport_public_key: &[u8],
    expiry_ns: u64,
    nonce: u64,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(b"ICP Stealth Authorization:");
    body.extend_from_slice(b"\naddress: 0x");
    body.extend_from_slice(hex::encode(address).as_bytes());
    body.extend_from_slice(b"\ncanister: ");
    body.extend_from_slice(canister_id.to_text().as_bytes());
    body.extend_from_slice(b"\ntransport: 0x");
    body.extend_from_slice(hex::encode(transport_public_key).as_bytes());
    body.extend_from_slice(b"\nexpiry_ns:");
    body.extend_from_slice(expiry_ns.to_string().as_bytes());
    body.extend_from_slice(b"\nnonce:");
    body.extend_from_slice(nonce.to_string().as_bytes());

    let prefix = format!("\x19Ethereum Signed Message:\n{}", body.len());
    let mut message = Vec::with_capacity(prefix.len() + body.len());
    message.extend_from_slice(prefix.as_bytes());
    message.extend_from_slice(&body);
    message
}

fn recover_address(message: &[u8], signature: &[u8]) -> Result<Address, String> {
    if signature.len() != 65 {
        return Err("signature must be 65 bytes (r||s||v)".to_string());
    }
    let mut sig = [0u8; 65];
    sig.copy_from_slice(signature);

    let signature = Signature::try_from(&sig[..64]).map_err(|_| "invalid signature".to_string())?;
    let v = match sig[64] {
        27 | 28 => sig[64] - 27,
        other => other,
    };
    let recovery_id = RecoveryId::from_byte(v).ok_or_else(|| "invalid recovery id".to_string())?;
    let digest = Keccak256::new_with_prefix(message);
    let verify_key = VerifyingKey::recover_from_digest(digest, &signature, recovery_id)
        .map_err(|_| "failed to recover signer".to_string())?;
    let encoded = verify_key.to_encoded_point(false);
    let public_key = encoded.as_bytes();
    if public_key.len() != 65 {
        return Err("unexpected public key length".to_string());
    }
    let hashed = Keccak256::digest(&public_key[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hashed[12..]);
    Ok(address)
}

ic_cdk::export_candid!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_message_format() {
        let address = [0u8; 20];
        let msg = authorization_message_with_canister(
            Principal::management_canister(),
            &address,
            &[1, 2, 3],
            42,
            7,
        );
        assert!(msg.starts_with(b"\x19Ethereum Signed Message:\n"));
    }
}
