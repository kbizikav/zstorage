import { DerivedPublicKey, EncryptedVetKey, TransportSecretKey, } from '@dfinity/vetkeys';
import { StealthError } from './errors';
export function prepareTransportKey() {
    const secret = TransportSecretKey.random();
    const publicKey = secret.publicKeyBytes();
    return { secret, publicKey };
}
export function decryptVetKey(encryptedKey, viewPublicKey, transportSecret, identity = new Uint8Array()) {
    try {
        const encrypted = EncryptedVetKey.deserialize(encryptedKey);
        const derived = DerivedPublicKey.deserialize(viewPublicKey);
        return encrypted.decryptAndVerify(transportSecret, derived, identity);
    }
    catch (error) {
        if (error instanceof StealthError) {
            throw error;
        }
        throw new StealthError('failed to decrypt vet key');
    }
}
