# ICP Stealth Announcement Protocol Specification

## 1. Objectives

- Enable stealth payment announcements on the Internet Computer Protocol (ICP) without requiring recipients to pre-register public keys.
- Leverage the vetKD (verifiably encrypted threshold key derivation) service so that the key manager canister deterministically derives viewing keys from a master vetKey while only recipients learn the corresponding private material.
- Incorporate a one-byte view tag scheme compatible with the efficiency goals of ERC‑5564 so recipients can filter announcements quickly.

## 2. Actors & Components

- **Sender**: Prepares an encrypted payload for a recipient and writes the announcement to storage.
- **Recipient**: Controls an EVM-compatible address, registers an authenticated transport key, and scans announcements to find messages addressed to them.
- **Key manager canister**:
  - Holds configuration for a vetKD master key (e.g., `key_1` / `test_key_1` on mainnet/devnet).
  - Derives per-recipient viewing key material on demand using vetKD without storing recipient secrets.
  - Issues encrypted vetKeys to authenticated recipients using recipient-supplied transport keys.
- **Storage canister**: Persists encrypted announcements (including ephemeral public key, view tag, and ciphertext metadata) and exposes paginated retrieval APIs.
- **Client libraries (Rust & TypeScript)**: Wrap both canisters, provide key derivation helpers for senders/recipients, and implement encryption & scanning utilities.

## 3. Cryptographic Foundations

### 3.1 vetKD master configuration

- The key manager ships with the vetKD key identifier `VetKDKeyId { curve: bls12_381_g2, name: "key_1" }` (switchable to `"test_key_1"` in non-prod) and a domain separator `context = b"icp-stealth-announcement-v1"`.
- The matching master public key bytes are stored in configuration and loaded into a `MasterPublicKey` helper at init time so the key manager can derive viewing public keys without management canister calls.
- Inputs to `vetkd_derive_key` use `input = H(address || scheme_id)` where `address` is the 20‑byte EVM address and `scheme_id = b"icp-stealth-bls-g2-v1"` disambiguates future schemes.

### 3.2 Viewing key derivation (BLS12-381 G2)

1. When `get_view_public_key` is invoked, the key manager deterministically derives the viewing public key `v_pk` off-chain-equivalently by calling `MasterPublicKey::derive_canister_key(context, canister_id)` followed by `derive_sub_key(input)` with the supplied `address` and `scheme_id`.
2. Recipients later request the encrypted vetKey for their own transport key (see §3.4); the key manager never decrypts recipient secrets.
3. Upon decrypting the vetKey, the recipient interprets the 32-byte scalar modulo the subgroup order `r` to obtain the viewing private scalar `v_sk`.
4. Recipients can locally verify `v_pk` via `v_pk ?= v_sk * G2_BASE`. The key manager recomputes `v_pk` on every request, so no cache is maintained.

### 3.3 Sender encryption workflow

- Sender fetches `v_pk` (G2 point) from the key manager (`key_manager.get_view_public_key(address)`).
- Generate ephemeral BLS12-381 key pair by sampling `e_sk ∈ [1, r-1]` uniformly and computing `e_pk = e_sk * G2_BASE`.
- Compute shared point `S = e_sk * v_pk` (scalar multiplication on G2).
- Derive symmetric keys via HKDF over the compressed form of `S`:
  - `shared_bytes = bls12_381::G2Affine::from(S).to_compressed()`
  - `k_enc = HKDF(shared_bytes, salt="icp-stealth", info="aes-gcm-256")`.
  - `k_tag = HKDF(shared_bytes, salt="icp-stealth", info="view-tag")`.
- Produce `view_tag = first_byte(k_tag)` (EIP‑5564 compliant).citeturn0search2
- Encrypt the payload using AES‑GCM‑256 (nonce derived from HKDF or random 96-bit nonce).
- Submit the announcement to storage with `(address, e_pk_compressed, view_tag, ciphertext, nonce, payload_type_metadata)`, where `e_pk_compressed` is a 96-byte G2 encoding.

### 3.4 Recipient decryption workflow

1. Recipient generates a fresh transport secret using `ic_vetkeys::TransportSecretKey::random()`, derives `transport_public_key = secret.public_key()`, and retains the secret for decrypting the vetKey reply.
2. Recipient signs the authorization message (see §4.2) with their Web3 wallet and calls `key_manager.request_encrypted_view_key`.
3. The key manager verifies the signature, checks expiry, and calls the management-canister method
```
vetkd_derive_key : record {
    context : blob;
    input : blob;
    key_id : record { curve : vetkd_curve; name : text };
    transport_public_key : blob;
} -> record { encrypted_key : blob };
```
   by invoking `ic_cdk::management_canister::vetkd_derive_key(VetKDDeriveKeyArgs { ... })` with:
   - `context = context(caller)` — the domain separator plus caller principal bytes, ensuring outputs bind to the requesting principal.
   - `input = address_bytes || scheme_id`.
   - `key_id = bls12_381_g2_test_key()` (or `key_1` in production).
   - `transport_public_key = transport_pub` (the vetKD transport public key output by `ic_vetkeys::TransportSecretKey::public_key()`).
   The management canister replies with `EncryptedKeyReply { encrypted_key }`, a vetKey ciphertext decryptable only by the caller’s transport secret.
   The key manager never observes the vetKey plaintext.
4. Recipient decrypts and verifies the vetKey locally, reconstructs `v_sk`, and continuously scans storage:
   - Pull the latest `N` announcements (default 1,000).
   - Deserialize each stored `e_pk` into a G2 point and compute shared point `S = v_sk * e_pk`.
   - Derive `shared_bytes`, `k_tag`, and `k_enc` as above.
   - Filter by matching `view_tag == first_byte(k_tag)`; for matches, decrypt ciphertext using `k_enc`.

## 4. Canister Interfaces

### 4.1 Key manager canister (`key_manager/src/lib.rs`)

State:
- Config: `{ key_id, context, master_public_key }`.
- Replay protection map for signed requests `(address, nonce, expiry)` to prevent reuse.

Public methods:

| Method | Type | Description |
| --- | --- | --- |
| `get_master_public_key() -> Vec<u8>` | query | Returns serialized vetKD master public key for clients that prefer offline derivation checks. |
| `get_view_public_key(address: [u8; 20]) -> ViewPublicResponse` | query | Derives and returns the BLS12-381 G2 viewing public key plus metadata (derivation height, scheme_id). |
| `request_encrypted_view_key(req: EncryptedKeyRequest) -> EncryptedKeyResponse` | update | Verifies wallet signature, expiry, and replay nonce, then returns `{ encrypted_key, derived_public_key_bytes }` encrypted to the caller’s supplied one-time transport public key. |

Authorization message (EIP‑191 style):
```
ICP Stealth View Key Request
Address: 0x<recipient_hex>
TransportPub: <base64>
Expiry: <ISO8601 UTC>
Nonce: <u64>
```
The recipient’s wallet signs the keccak256 hash of the UTF‑8 message, yielding a secp256k1 signature that the canister verifies using `libsecp256k1`.

### 4.2 Storage canister (`storage/src/lib.rs`)

State:
- Rolling vector of `Announcement` records with capped length (configurable, default 50,000).
- Optional index on view tag byte frequency for metrics.

Record layout:
```
struct Announcement {
    ephemeral_pubkey: Vec<u8>,   // Compressed BLS12-381 G2 (96 bytes)
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
| `announce(payload: AnnouncementInput)` | update | Validates sizes, stores announcement, evicts oldest entries when capacity exceeded; callable by any principal (no cycles required from caller). |
| `list_recent(limit: u32, cursor: Option<u64>) -> Vec<Announcement>` | query | Returns the most recent announcements capped at 1,000 per call. |
| `latest_index() -> u64` | query | Provides the latest announcement index for incremental polling. |

Business rules:
- Payload size hard limit (e.g., 8 KB) to control cycles and storage.
- Nonce uniqueness enforced per `(view_tag, nonce)` to resist straightforward replay (combined with ciphertext authentication).
- Optional spam mitigation (rate limits, deposits) remains future work.

## 5. Client Libraries

### 5.1 Rust library (`client/src/lib.rs`, published internally as `icp-stealth-client`)

Modules:

- `config`: Loads canister IDs and vetKD key settings.
- `sender`:
  - `fetch_view_key(address)` via key manager Candid.
  - `generate_ephemeral()` using `bls12_381` scalar sampling on G2.
  - `encrypt_payload(address, plaintext, metadata)` returning `AnnouncementInput`.
- `recipient`:
  - `prepare_transport_key()` (ephemeral transport pair for vetKD delivery produced via `ic_vetkeys::TransportSecretKey::random()`).
  - `sign_request(address, transport_pub, expiry, nonce, signer)` helper.
  - `decrypt_vet_key(encrypted_key, derived_public, transport_secret)`.
  - `scan_announcements(v_sk, announcements)` returning decrypted messages.
- `types`: Shared structs matching Candid definitions (generated via `ic_cdk::export_candid!`).

Testing:
- Unit tests for HKDF derivations and tag matching.
- Integration test using `pocket-ic` to deploy both canisters and verify end‑to‑end message delivery with randomized announcements.

### 5.2 TypeScript library (published as `@icp/stealth-client`)

Packages & structure:

- `config.ts`: Loads canister IDs, vetKD key identifiers, and exposes typed configuration helpers for Node.js and browser targets.
- `sender.ts`:
  - `fetchViewKey(address)` via the key manager canister (through `@dfinity/agent`).
  - `generateEphemeral()` using a wasm bridge to the Rust `bls12_381` implementation (compiled with `wasm-bindgen`), falling back to a pure JS path for tests.
  - `encryptPayload(address, plaintext, metadata)` returning an `AnnouncementInput` object aligned with the candid definition.
- `recipient.ts`:
  - `prepareTransportKey()` invoking the wasm build of `ic-vetkeys` to call `TransportSecretKey::random()` and expose `{ publicKey, secretKey }`.
  - `signRequest(address, transportPub, expiry, nonce, signer)` helper that works with both `ethers` and raw secp256k1 providers.
  - `decryptVetKey(encryptedKey, derivedPublic, transportSecret)` returning the viewing scalar.
  - `scanAnnouncements(vSk, announcements)` mirroring the Rust logic, including view-tag filtering.
- `types.ts`: Shared TS interfaces generated from the candid definitions via `didc` + `@dfinity/candid`.

Testing:
- Browser-focused integration test harness using `@dfinity/agent` against a `pocket-ic` instance in CI.
- Node.js unit tests that assert deterministic HKDF output and vetKD round-trips using the wasm bindings.

## 6. Local Testing Workflows

### 6.1 `dfx` local replica

- Start a clean replica with `dfx start --background --clean --host 127.0.0.1:4943` so both canisters can be deployed against the default local endpoint.citeturn1search0
- Deploy `key_manager` and `storage` using the same candid as mainnet, then point both client libraries at `http://127.0.0.1:4943` via the shared local network binding.
- Configure vetKD to use the built-in `dfx_test_key` (`VetKDKeyId { curve: bls12_381_g2, name: "dfx_test_key" }`), which the local replica exposes specifically for developer vetKD flows; mirror that key name in the key manager configuration when targeting localnet.citeturn2search1
- Use `dfx canister call ...` commands (adapting the ledger examples to `key_manager.get_view_public_key`) to seed fixture data and confirm viewing key derivations before sending encrypted announcements.citeturn4search0

### 6.2 PocketIC automation

- Integrate the `pocket-ic` crate in Rust integration tests to spin up lightweight replicas entirely in-process; deploy both canisters, mint sample announcements, and assert end-to-end decryption without hitting an external `dfx` process.citeturn3search5
- Reuse the same PocketIC workflow for the TypeScript library by targeting the PocketIC REST API from the JavaScript client, using the same binary configured via the `POCKET_IC_BIN` environment variable in CI.citeturn3search5
- Make sure the wasm bundles for `bls12_381` and `ic-vetkeys` are built ahead of the PocketIC run so tests can load them without network access constraints.

## 7. Data Formats & Serialization

- Use candid IDL for canister interfaces; `ic-cdk::export_candid!` to emit `.did`.
- Binary fields (keys, ciphertext) encoded as `Vec<u8>` on the wire; client library provides hex/base64 helpers.
- Timestamps use nanoseconds since Unix epoch (`u64`) per `ic_cdk::api::time()`.

## 8. Security Considerations

- **Transport key confidentiality**: Recipients must regenerate fresh transport key pairs per request; the key manager only processes the provided public key and never retains transport secrets.
- **Request replay**: Nonce + expiry validated on the key manager to prevent malicious reuse of signed authorizations.
- **Cycle costs**: `vetkd_derive_key` requires a management-canister call per request; document expected cycle burn on mainnet/testnet and ensure controllers provision sufficient cycles for high-frequency key requests.
- **View tag leakage**: One byte of shared secret is exposed, reducing brute-force resistance to 124 bits—acceptable per ERC‑5564 rationale.citeturn0search2
- **Payload limits**: Enforce max plaintext length and validate metadata to mitigate DoS.
