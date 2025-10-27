import { keccak_256 } from '@noble/hashes/sha3';
import { utf8ToBytes } from '@noble/hashes/utils';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { etc, getPublicKey, sign } from '@noble/secp256k1';
const encoder = new TextEncoder();
const decoder = new TextDecoder();
export function deriveAddress(privateKey) {
    if (privateKey.length !== 32) {
        throw new Error('private key must be 32 bytes');
    }
    const uncompressed = getPublicKey(privateKey, false);
    const publicKey = uncompressed.slice(1);
    const hash = keccak_256(publicKey);
    return Uint8Array.from(hash.slice(12));
}
export function authorizationMessage(canisterId, address, transportPublicKey, expiryNs, nonce) {
    const message = `ICP Stealth Authorization:\naddress: 0x${bytesToHex(address)}\ncanister: ${canisterId.toText()}\ntransport: 0x${bytesToHex(transportPublicKey)}\nexpiry_ns:${expiryNs}\nnonce:${nonce}`;
    return eip191Message(utf8ToBytes(message));
}
export function signAuthorization(message, privateKey) {
    if (message.length === 0) {
        throw new Error('message must not be empty');
    }
    if (privateKey.length !== 32) {
        throw new Error('private key must be 32 bytes');
    }
    const digest = keccak_256(message);
    ensureHmac();
    const signature = sign(digest, privateKey);
    const compact = signature.toCompactRawBytes();
    const bytes = new Uint8Array(65);
    bytes.set(compact, 0);
    const recovery = signature.recovery ?? 0;
    bytes[64] = recovery + 27;
    return bytes;
}
export function unixTimeNs() {
    const nowMs = BigInt(Date.now());
    return nowMs * 1000000n;
}
export function bytesToHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
export function hexToBytes(hex) {
    const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
    if (normalized.length % 2 !== 0) {
        throw new Error('hex string must have even length');
    }
    const bytes = new Uint8Array(normalized.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
function eip191Message(message) {
    const prefix = `\x19Ethereum Signed Message:\n${message.length}`;
    const prefixBytes = encoder.encode(prefix);
    const result = new Uint8Array(prefixBytes.length + message.length);
    result.set(prefixBytes, 0);
    result.set(message, prefixBytes.length);
    return result;
}
export function addressToHex(address) {
    return `0x${bytesToHex(address)}`;
}
export function messageToString(message) {
    return decoder.decode(message);
}
function ensureHmac() {
    if (!etc.hmacSha256Sync) {
        etc.hmacSha256Sync = (key, ...msgs) => {
            const data = msgs.length === 0
                ? new Uint8Array()
                : msgs.length === 1
                    ? msgs[0]
                    : etc.concatBytes(...msgs);
            return hmac(sha256, key, data);
        };
    }
}
