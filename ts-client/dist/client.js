import { Actor } from '@dfinity/agent';
import { StealthError } from './errors';
export class StealthCanisterClient {
    constructor(agent, storageCanisterId, keyManagerCanisterId) {
        this.agent = agent;
        this.storageCanisterId = storageCanisterId;
        this.keyManagerCanisterId = keyManagerCanisterId;
        this.keyManagerActor = null;
        this.storageActor = null;
    }
    getAgent() {
        return this.agent;
    }
    getStorageCanisterId() {
        return this.storageCanisterId;
    }
    getKeyManagerCanisterId() {
        return this.keyManagerCanisterId;
    }
    async getViewPublicKey(address) {
        const actor = await this.getKeyManagerActor();
        const result = await actor.get_view_public_key(address);
        return unwrapResult(result, 'get_view_public_key');
    }
    async requestEncryptedViewKey(request) {
        const actor = await this.getKeyManagerActor();
        const result = await actor.request_encrypted_view_key(toCandidEncryptedViewKeyRequest(request));
        return unwrapResult(result, 'request_encrypted_view_key');
    }
    async getMaxNonce(address) {
        const actor = await this.getKeyManagerActor();
        const result = await actor.get_max_nonce(address);
        return unwrapResult(result, 'get_max_nonce');
    }
    async submitAnnouncement(input) {
        const actor = await this.getStorageActor();
        const candidAnnouncement = await actor.submit_announcement(toCandidAnnouncementInput(input));
        return mapAnnouncement(candidAnnouncement);
    }
    async listAnnouncements(startAfter, limit) {
        const actor = await this.getStorageActor();
        const start = (startAfter === undefined ? [] : [startAfter]);
        const cappedLimit = (limit === undefined ? [] : [limit]);
        const page = await actor.list_announcements(start, cappedLimit);
        return {
            announcements: page.announcements.map(mapAnnouncement),
            nextId: page.next_id.length === 0 ? null : page.next_id[0],
        };
    }
    async getAnnouncement(id) {
        const actor = await this.getStorageActor();
        const result = await actor.get_announcement(id);
        if (result.length === 0) {
            return null;
        }
        return mapAnnouncement(result[0]);
    }
    async getKeyManagerActor() {
        if (this.keyManagerActor) {
            return this.keyManagerActor;
        }
        this.keyManagerActor = Actor.createActor(keyManagerIdlFactory, {
            agent: this.agent,
            canisterId: this.keyManagerCanisterId,
        });
        return this.keyManagerActor;
    }
    async getStorageActor() {
        if (this.storageActor) {
            return this.storageActor;
        }
        this.storageActor = Actor.createActor(storageIdlFactory, {
            agent: this.agent,
            canisterId: this.storageCanisterId,
        });
        return this.storageActor;
    }
}
function unwrapResult(result, method) {
    if ('Ok' in result) {
        return result.Ok;
    }
    throw new StealthError(`${method} failed: ${result.Err}`);
}
function mapAnnouncement(announcement) {
    return {
        id: announcement.id,
        ibeCiphertext: announcement.ibe_ciphertext,
        ciphertext: announcement.ciphertext,
        nonce: announcement.nonce,
        createdAtNs: announcement.created_at_ns,
    };
}
function toCandidAnnouncementInput(input) {
    return {
        ibe_ciphertext: input.ibeCiphertext,
        ciphertext: input.ciphertext,
        nonce: input.nonce,
    };
}
function toCandidEncryptedViewKeyRequest(request) {
    return {
        address: request.address,
        transport_public_key: request.transportPublicKey,
        expiry_ns: request.expiryNs,
        nonce: request.nonce,
        signature: request.signature,
    };
}
const keyManagerIdlFactory = ({ IDL: idl }) => {
    const Address = idl.Vec(idl.Nat8);
    const PublicKey = idl.Vec(idl.Nat8);
    const Signature = idl.Vec(idl.Nat8);
    const EncryptedKey = idl.Vec(idl.Nat8);
    const EncryptedViewKeyRequest = idl.Record({
        address: Address,
        transport_public_key: PublicKey,
        expiry_ns: idl.Nat64,
        nonce: idl.Nat64,
        signature: Signature,
    });
    const ResultPublicKey = idl.Variant({ Ok: PublicKey, Err: idl.Text });
    const ResultEncryptedKey = idl.Variant({ Ok: EncryptedKey, Err: idl.Text });
    const ResultNonce = idl.Variant({ Ok: idl.Nat64, Err: idl.Text });
    return idl.Service({
        get_view_public_key: idl.Func([Address], [ResultPublicKey], []),
        request_encrypted_view_key: idl.Func([EncryptedViewKeyRequest], [ResultEncryptedKey], []),
        get_max_nonce: idl.Func([Address], [ResultNonce], ['query']),
    });
};
const storageIdlFactory = ({ IDL: idl }) => {
    const AnnouncementInput = idl.Record({
        ibe_ciphertext: idl.Vec(idl.Nat8),
        ciphertext: idl.Vec(idl.Nat8),
        nonce: idl.Vec(idl.Nat8),
    });
    const Announcement = idl.Record({
        id: idl.Nat64,
        ibe_ciphertext: idl.Vec(idl.Nat8),
        ciphertext: idl.Vec(idl.Nat8),
        nonce: idl.Vec(idl.Nat8),
        created_at_ns: idl.Nat64,
    });
    const AnnouncementPage = idl.Record({
        announcements: idl.Vec(Announcement),
        next_id: idl.Opt(idl.Nat64),
    });
    return idl.Service({
        submit_announcement: idl.Func([AnnouncementInput], [Announcement], []),
        list_announcements: idl.Func([idl.Opt(idl.Nat64), idl.Opt(idl.Nat32)], [AnnouncementPage], ['query']),
        get_announcement: idl.Func([idl.Nat64], [idl.Opt(Announcement)], ['query']),
    });
};
