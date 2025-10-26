# ICP Stealth Announcement Protocol Specification

## 1. Objectives

- Deliver stealth payment announcements on the Internet Computer Protocol (ICP) without forcing recipients to pre-register public keys.
- Leverage vetKD (verifiably encrypted threshold key derivation) so the key manager canister derives viewing keys from a shared vetKey while recipients alone recover the secret material.
- Retain compatibility with the ERC-5564 one-byte view tag scheme so recipients can filter announcements efficiently.

## 2. Actors and Components

- **Sender** - Encrypts a payload for the recipient and publishes the announcement to the storage canister.
- **Recipient** - Controls an EVM-compatible address, registers a transport key, and scans announcements for messages addressed to that address.
- **Key manager canister**
  - Stores vetKD configuration (key identifier, domain separator, optional master public key bytes).
  - Derives per-recipient viewing keys through management canister vetKD calls without persisting recipient secrets.
  - Issues encrypted vetKeys to authenticated recipients using recipient supplied transport keys.
- **Storage canister** - Persists announcement records (ephemeral public key, view tag, ciphertext, metadata) and exposes paginated query APIs.
- **Client libraries (Rust / TypeScript)** - Provide high-level helpers for senders and recipients, including key derivation, encryption, and scanning logic.

## 3. Cryptographic Foundations

### 3.1 vetKD Master Configuration

- The key manager is provisioned with `VetKDKeyId { curve: bls12_381_g2, name: "key_1" }` on mainnet (or `"test_key_1"` / `"dfx_test_key"` on development networks) and a domain separator `context = b"icp-stealth-announcement-v1"`.
- The corresponding master public key bytes may be stored in configuration for clients that need to verify viewing keys offline, but canister derivations rely exclusively on vetKD system calls.
- Inputs to `vetkd_derive_key` currently use an empty vector (`input = []`); the derivation is fully bound by the context field.

### 3.2 Viewing Key Derivation (BLS12-381 G2)

1. `get_view_public_key` invokes the management canister vetKD public key API. The request uses the recipient address bytes in the context to keep the derivation aligned with the later encrypted key flow.
   ```rust
   use ic_cdk::management_canister::{vetkd_public_key, VetKDPublicKeyArgs};

   async fn vetkd_public_key_for(address: [u8; 20]) -> Vec<u8> {
       let request = VetKDPublicKeyArgs {
           canister_id: None,
           context: context(address), // domain separator || address bytes
           key_id: bls12_381_g2_test_key(),
       };

       let reply = vetkd_public_key(&request)
           .await
           .expect("failed to derive vetKD public key");
       reply.public_key
   }
   ```
   _Note:_ the same public key derivation can be reproduced off-chain with the published vetKD algorithms; the system call simply delegates the canonical computation to the IC.
2. The key manager never caches the result. It recomputes `v_pk` on each query to avoid storing recipient state.
3. Recipients who later decrypt a vetKD response can verify correctness by checking `v_pk == v_sk * G2_BASE`.

### 3.3 Sender Encryption Workflow

1. Fetch the recipient viewing key `v_pk` from the key manager.
2. Sample an ephemeral scalar `e_sk ∈ [1, r-1]` and compute the compressed G2 point `e_pk = e_sk * G2_BASE`.
3. Derive the shared point `S = e_sk * v_pk`, convert it to compressed bytes, and feed HKDF with salt `"icp-stealth"` to obtain:
   - `k_enc` using info `"aes-gcm-256"`.
   - `k_tag` using info `"view-tag"`.
4. Produce `view_tag = k_tag[0]` (one byte).
5. Encrypt the payload with AES-GCM-256, using either a random 96-bit nonce or one produced deterministically by HKDF.
6. Submit the announcement `{ e_pk_compressed, view_tag, ciphertext, nonce, payload_type, metadata }` to the storage canister.

### 3.4 Recipient Decryption Workflow

1. Generate a fresh transport secret via `ic_vetkeys::TransportSecretKey::random()` and expose the public component to the key manager.
2. Sign the authorization message (see §4.2) with the wallet that controls the 20-byte address, then call `key_manager.request_encrypted_view_key`.
3. The key manager validates expiry, nonce, and signature, then calls `ic_cdk::management_canister::vetkd_derive_key` with:
   - `context = context(address_bytes)` (domain separator concatenated with the recipient address).
   - `input = []` (empty vector).
   - `key_id = bls12_381_g2_test_key()` (or `"key_1"` in production).
   - `transport_public_key` supplied by the recipient.
   The management canister returns `encrypted_key`, which only the recipient can decrypt with the matching transport secret.
4. The recipient decrypts the vetKD payload to recover the viewing scalar `v_sk`, scans announcements, filters by matching `view_tag`, and decrypts ciphertexts using the shared secret derived from `v_sk` and each announcement’s `e_pk`.

## 4. Canister Interfaces

### 4.1 Key Manager (`key_manager/src/lib.rs`)

State:
- vetKD configuration (`key_id`, `context`, optional `master_public_key` bytes).
- Replay protection map keyed by `(address, nonce)` with expiry timestamps.

Public methods:

| Method | Type | Description |
| --- | --- | --- |
| `get_master_public_key() -> Vec<u8>` | query | Returns the configured vetKD master public key for offline verification. |
| `get_view_public_key(address: [u8; 20]) -> ViewPublicKeyResponse` | query | Calls `vetkd_public_key` and returns the compressed G2 viewing key plus metadata. |
| `request_encrypted_view_key(req: EncryptedViewKeyRequest) -> EncryptedViewKeyResponse` | update | Verifies the wallet signature, enforces nonce/expiry, invokes `vetkd_derive_key`, and returns the encrypted vetKey bound to the recipient’s transport key. |

Authorization message (EIP-191 style):
```
ICP Stealth View Key Request
Address: 0x<recipient_hex>
TransportPub: <base64>
Expiry: <ISO8601 UTC>
Nonce: <u64>
```

### 4.2 Storage (`storage/src/lib.rs`)

State:
- Vector of `Announcement` records with an optional capacity cap.
- Derived metrics (e.g., counts by `view_tag`) if needed.

Record layout:
```
struct Announcement {
    ephemeral_pubkey: Vec<u8>,  // Compressed BLS12-381 G2 (96 bytes)
    view_tag: u8,
    metadata_version: u8,
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
    posted_at_ns: u64,
}
```

Public methods:

| Method | Type | Description |
| --- | --- | --- |
| `announce(payload: AnnouncementInput)` | update | Validates sizes, appends the announcement, and performs eviction if the capacity limit is reached. |
| `list_recent(limit: u32, cursor: Option<u64>) -> Vec<Announcement>` | query | Returns the newest announcements up to a limit (default cap of 1,000). |
| `latest_index() -> u64` | query | Exposes the most recent announcement index for incremental polling. |

Business rules:
- Enforce strict payload size limits to control cycles and storage usage.
- Track `(view_tag, nonce)` pairs to detect trivial replay within a recent window.
- Consider rate limiting or deposits for spam mitigation in future iterations.

## 5. Client Libraries

### 5.1 Rust Crate (`crates/stealth_client`)

- `config` - Shared constants and helper functions for canister IDs and vetKD key identifiers.
- `sender` - Fetches viewing keys, generates ephemeral keys, and encrypts payloads into `AnnouncementInput`.
- `recipient` - Manages transport keys, prepares signed requests, decrypts vetKD replies, and scans announcements.
- `types` - Rust structs mirroring the candid interface exported by the canisters.
- Testing - Unit tests for HKDF/tag derivations and integration tests using PocketIC to validate end-to-end flows.

### 5.2 TypeScript Package (`ts-client`)

- `config.ts` - Loads canister IDs and vetKD settings for Node.js and browser environments.
- `sender.ts` - Fetches viewing keys through `@dfinity/agent`, generates ephemeral keys (via WASM or pure JS fallback), and returns announcement payloads.
- `recipient.ts` - Wraps vetKD transport key generation, authorization signing helpers, vetKD decryption, and storage scanning logic.
- `types.ts` - Type definitions generated from candid using `didc` and re-exported for consumers.
- Testing - Browser and Node.js suites that exercise HKDF determinism, vetKD round-trips, and PocketIC-backed integration flows.

## 6. Local Testing Workflows

### 6.1 `dfx` Replica

1. Start a clean replica: `dfx start --background --clean --host 127.0.0.1:4943`.
2. Deploy the key manager and storage canisters; configure `dfx_test_key` (or another development key ID) in the key manager settings.
3. Use `dfx canister call` commands to request viewing keys and encrypted vetKeys while iterating on the client libraries.

### 6.2 PocketIC Automation

1. Use the `pocket-ic` crate in Rust integration tests to spin up an in-process replica, deploy both canisters, and assert sender/recipient flows without running an external `dfx` process.
2. Reuse the same binary in TypeScript integration tests by targeting the PocketIC REST API and keeping WASM bundles pre-built for offline execution.

## 7. Data Formats and Serialization

- All canister interfaces use candid; both Rust and TypeScript code generation rely on `ic_cdk::export_candid!`.
- Binary values (keys, ciphertexts, nonces) are encoded as `Vec<u8>` / `Uint8Array`. Helper utilities expose hex and base64 representations for user interfaces.
- Timestamps use nanoseconds since Unix epoch (`u64`) sourced from `ic_cdk::api::time()`.

## 8. Security Considerations

- **Transport key confidentiality** - Recipients must generate new transport key pairs per request; only the encrypted vetKey leaves the management canister.
- **Replay protection** - Signed requests include nonces and expiries enforced by the key manager to block replayed authorizations.
- **Cycle budgeting** - Each `vetkd_derive_key` call incurs management canister cycles; controllers must provision adequate cycles for high-volume use.
- **View tag leakage** - Exposing a single byte of `k_tag` enables fast filtering while leaving 124 bits of secrecy, consistent with ERC-5564 goals.
- **Payload hygiene** - Hard limits on plaintext and metadata sizes help prevent denial-of-service via oversized submissions.
