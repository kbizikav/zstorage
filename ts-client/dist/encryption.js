import { DerivedPublicKey, IbeCiphertext, IbeIdentity, IbeSeed, } from '@dfinity/vetkeys';
import { AnnouncementIgnoredError, StealthError } from './errors';
const SESSION_KEY_LEN = 32;
const NONCE_LEN = 12;
export async function encryptAnnouncement(viewPublicKey, plaintext, options = {}) {
    const { announcement } = await encryptAnnouncementWithArtifacts(viewPublicKey, plaintext, options);
    return announcement;
}
export async function encryptAnnouncementWithArtifacts(viewPublicKey, plaintextInput, options = {}) {
    const crypto = await resolveCrypto();
    const plaintext = typeof plaintextInput === 'string' ? new TextEncoder().encode(plaintextInput) : plaintextInput;
    const derivedPublicKey = DerivedPublicKey.deserialize(viewPublicKey);
    const identityBytes = options.identity ?? new Uint8Array();
    const identity = IbeIdentity.fromBytes(identityBytes);
    const sessionKey = options.randomBytes ? options.randomBytes(SESSION_KEY_LEN) : fillRandom(SESSION_KEY_LEN, crypto);
    if (sessionKey.length !== SESSION_KEY_LEN) {
        throw new StealthError(`session key must be ${SESSION_KEY_LEN} bytes`);
    }
    const nonce = options.randomBytes ? options.randomBytes(NONCE_LEN) : fillRandom(NONCE_LEN, crypto);
    if (nonce.length !== NONCE_LEN) {
        throw new StealthError(`nonce must be ${NONCE_LEN} bytes`);
    }
    const cryptoKey = await crypto.subtle.importKey('raw', sessionKey.buffer, { name: 'AES-GCM' }, false, ['encrypt']);
    const ciphertextBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, cryptoKey, plaintext);
    const ciphertext = new Uint8Array(ciphertextBuffer);
    const seedBytes = options.seed ?? fillRandom(32, crypto);
    const seed = IbeSeed.fromBytes(seedBytes);
    const ibeCiphertext = IbeCiphertext.encrypt(derivedPublicKey, identity, sessionKey, seed).serialize();
    const sessionKeyCopy = new Uint8Array(sessionKey);
    zeroMemory(sessionKey);
    return {
        announcement: {
            ibeCiphertext,
            ciphertext,
            nonce,
        },
        sessionKey: sessionKeyCopy,
    };
}
export async function decryptAnnouncement(vetKey, announcement) {
    const crypto = await resolveCrypto();
    const { ibeCiphertext, ciphertext, nonce } = announcement;
    const ibe = IbeCiphertext.deserialize(ibeCiphertext);
    let sessionKey;
    try {
        sessionKey = ibe.decrypt(vetKey);
    }
    catch (error) {
        throw new AnnouncementIgnoredError('vet key mismatch or invalid ciphertext');
    }
    if (sessionKey.length !== SESSION_KEY_LEN) {
        throw new AnnouncementIgnoredError('unexpected session key length');
    }
    const cryptoKey = await crypto.subtle.importKey('raw', sessionKey.buffer, { name: 'AES-GCM' }, false, ['decrypt']);
    if (nonce.length !== NONCE_LEN) {
        throw new AnnouncementIgnoredError('invalid nonce length');
    }
    try {
        const plaintextBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, cryptoKey, ciphertext);
        const plaintext = new Uint8Array(plaintextBuffer);
        zeroMemory(sessionKey);
        return {
            id: announcement.id,
            plaintext,
            createdAtNs: announcement.createdAtNs,
        };
    }
    catch (error) {
        zeroMemory(sessionKey);
        throw new AnnouncementIgnoredError('ciphertext authentication failed');
    }
}
export async function scanAnnouncements(vetKey, announcements) {
    const decrypted = [];
    for (const announcement of announcements) {
        try {
            const result = await decryptAnnouncement(vetKey, announcement);
            decrypted.push(result);
        }
        catch (error) {
            if (!(error instanceof AnnouncementIgnoredError)) {
                throw error;
            }
        }
    }
    return decrypted;
}
async function resolveCrypto() {
    if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
        return globalThis.crypto;
    }
    if (typeof process !== 'undefined' && process.versions?.node) {
        const { webcrypto } = await import('node:crypto');
        if (webcrypto?.subtle) {
            return webcrypto;
        }
    }
    throw new StealthError('WebCrypto API not available. Provide a crypto implementation via globalThis.crypto.');
}
function fillRandom(length, crypto) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
}
function zeroMemory(bytes) {
    bytes.fill(0);
}
