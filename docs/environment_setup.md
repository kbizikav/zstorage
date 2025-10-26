# Docs Project Environment Setup

Use this guide to prepare a local development workstation for contributing to the stealth announcement documentation and supporting code samples. The steps assume macOS or Linux. On Windows, use WSL2 with an Ubuntu distribution and follow the same instructions inside the Linux environment.

## 1. System Prerequisites

- Install build essentials (`build-essential`, `clang`, `cmake`, `pkg-config`, `git`, `openssl`, `libssl-dev`) via your OS package manager.
- Ensure OpenSSL headers are present (`brew install openssl@3` on macOS, `sudo apt install libssl-dev` on Ubuntu).
- Allocate at least 20 GB of free disk space for toolchains, replicas, and build artifacts.

## 2. Rust Toolchain

- Install rustup (https://rustup.rs) if it is not already present.
- Run `rustup toolchain install stable` and set it as default with `rustup default stable`.
- Add required targets:
  - `rustup target add wasm32-unknown-unknown`
  - `rustup target add wasm32-wasi`
- Add the following components: `rustup component add clippy rustfmt`.
- Verify with `rustc --version` and `cargo --version`.

## 3. Node.js & Package Managers

- Install Node.js 20 LTS or newer (via `nvm`, `asdf`, or the official installer).
- Ensure `npm` ≥ 10 is available. If the project standardizes on `pnpm` or `yarn`, install it globally.
- Install `wasm-pack` (`cargo install wasm-pack`) for building the WebAssembly helpers consumed by the TypeScript client.
- Optional: install `nvm` to simplify switching Node.js versions.

## 4. DFX CLI (Internet Computer SDK)

- Install the DFINITY dfx CLI: `sh -ci "$(curl -fsSL https://internetcomputer.org/install.sh)"`.
- After installation, pin the project’s required version (for example `DFX_VERSION=0.20.1 dfx upgrade`) if a `.dfx-version` file is present.
- Confirm the install with `dfx --version`.
- Enable the default identities and start a local replica once to let dfx download dependencies: `dfx start --background --clean --host 127.0.0.1:4943` then `dfx stop`.

## 5. PocketIC for Local Testing

- Add the `pocket-ic` binary for deterministic in-process replica testing:
  - Install the crate: `cargo install pocket-ic`.
  - Export the binary path in your shell (`export POCKET_IC_BIN="$(which pocket-ic)"`).
- CI environments should cache the binary and set `POCKET_IC_BIN` before running integration tests.

## 6. Candid & Wasm Utilities

- Install the Candid compiler for type generation:
  - `cargo install ic-wasm`
  - `cargo install candid-extractor`
- Install `didc` (via `npm install -g @dfinity/agent` or download the release) if you generate TypeScript bindings from `.did` files.
- Keep `wasm-opt` (from Binaryen) available for release builds (`brew install binaryen` or `sudo apt install binaryen`).

## 7. Recommended VS Code Extensions

- `rust-lang.rust-analyzer`
- `ms-vscode.vscode-typescript-next`
- `dfinity-foundation.vscode-motoko` (for candid highlighting)
- `esbenp.prettier-vscode`

## 8. Environment Variables & Shell Setup

- Add the following exports to your shell profile (`.zshrc`, `.bashrc`):
  ```bash
  export DFX_NETWORK=local
  export POCKET_IC_BIN="${POCKET_IC_BIN:-$(which pocket-ic)}"
  export RUSTFLAGS="-C target-cpu=native"
  ```
- If you need to target multiple networks, override `DFX_NETWORK` per command (e.g., `DFX_NETWORK=ic` for mainnet).
- For reproducible builds, consider using `direnv` to load per-directory environment files.

## 9. Verifying the Setup

Run the following smoke tests:

```bash
# Validate Rust toolchain
cargo fmt --version
cargo clippy --version

# Check dfx replica
dfx start --background --clean --host 127.0.0.1:4943
dfx canister list
dfx stop

# Validate wasm-pack and pocket-ic
wasm-pack --version
pocket-ic --help
```

CI should also execute the project’s unit tests (`cargo test`, `npm test`) after the environment is primed.
