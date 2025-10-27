import { ActorMethod, Agent } from '@dfinity/agent';
import { Principal } from '@dfinity/principal';
import { Announcement, AnnouncementInput, AnnouncementPage, CanisterResult, EncryptedViewKeyRequest } from './types';
export type KeyManagerActor = {
    get_view_public_key: ActorMethod<[Uint8Array], CanisterResult<Uint8Array>>;
    request_encrypted_view_key: ActorMethod<[EncryptedViewKeyRequestCandid], CanisterResult<Uint8Array>>;
    get_max_nonce: ActorMethod<[Uint8Array], CanisterResult<bigint>>;
};
export interface AnnouncementInputCandid {
    ibe_ciphertext: Uint8Array;
    ciphertext: Uint8Array;
    nonce: Uint8Array;
}
export interface EncryptedViewKeyRequestCandid {
    address: Uint8Array;
    transport_public_key: Uint8Array;
    expiry_ns: bigint;
    nonce: bigint;
    signature: Uint8Array;
}
export type StorageActor = {
    submit_announcement: ActorMethod<[AnnouncementInputCandid], AnnouncementCandid>;
    list_announcements: ActorMethod<[[] | [bigint], [] | [number]], AnnouncementPageCandid>;
    get_announcement: ActorMethod<[bigint], [] | [AnnouncementCandid]>;
};
export interface AnnouncementCandid {
    id: bigint;
    ibe_ciphertext: Uint8Array;
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    created_at_ns: bigint;
}
export interface AnnouncementPageCandid {
    announcements: AnnouncementCandid[];
    next_id: [] | [bigint];
}
export declare class StealthCanisterClient {
    private readonly agent;
    private readonly storageCanisterId;
    private readonly keyManagerCanisterId;
    private keyManagerActor;
    private storageActor;
    constructor(agent: Agent, storageCanisterId: Principal, keyManagerCanisterId: Principal);
    getAgent(): Agent;
    getStorageCanisterId(): Principal;
    getKeyManagerCanisterId(): Principal;
    getViewPublicKey(address: Uint8Array): Promise<Uint8Array>;
    requestEncryptedViewKey(request: EncryptedViewKeyRequest): Promise<Uint8Array>;
    getMaxNonce(address: Uint8Array): Promise<bigint>;
    submitAnnouncement(input: AnnouncementInput): Promise<Announcement>;
    listAnnouncements(startAfter?: bigint, limit?: number): Promise<AnnouncementPage>;
    getAnnouncement(id: bigint): Promise<Announcement | null>;
    private getKeyManagerActor;
    private getStorageActor;
}
//# sourceMappingURL=client.d.ts.map