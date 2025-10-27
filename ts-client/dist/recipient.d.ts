import { TransportSecretKey, VetKey } from '@dfinity/vetkeys';
export interface TransportKeyPair {
    secret: TransportSecretKey;
    publicKey: Uint8Array;
}
export declare function prepareTransportKey(): TransportKeyPair;
export declare function decryptVetKey(encryptedKey: Uint8Array, viewPublicKey: Uint8Array, transportSecret: TransportSecretKey, identity?: Uint8Array): VetKey;
//# sourceMappingURL=recipient.d.ts.map