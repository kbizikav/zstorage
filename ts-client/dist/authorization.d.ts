import { Principal } from '@dfinity/principal';
export type Address = Uint8Array;
export declare function deriveAddress(privateKey: Uint8Array): Address;
export declare function authorizationMessage(canisterId: Principal, address: Address, transportPublicKey: Uint8Array, expiryNs: bigint, nonce: bigint): Uint8Array;
export declare function signAuthorization(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
export declare function unixTimeNs(): bigint;
export declare function bytesToHex(bytes: Uint8Array): string;
export declare function hexToBytes(hex: string): Uint8Array;
export declare function addressToHex(address: Address): string;
export declare function messageToString(message: Uint8Array): string;
//# sourceMappingURL=authorization.d.ts.map