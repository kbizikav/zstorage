import { Actor, ActorMethod, Agent } from '@dfinity/agent';
import { IDL } from '@dfinity/candid';
import { Principal } from '@dfinity/principal';

import {
  Announcement,
  AnnouncementInput,
  AnnouncementPage,
  CanisterResult,
  EncryptedViewKeyRequest,
} from './types';
import { StealthError } from './errors';

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

export class StealthCanisterClient {
  private keyManagerActor: KeyManagerActor | null = null;
  private storageActor: StorageActor | null = null;

  constructor(
    private readonly agent: Agent,
    private readonly storageCanisterId: Principal,
    private readonly keyManagerCanisterId: Principal,
  ) {}

  getAgent(): Agent {
    return this.agent;
  }

  getStorageCanisterId(): Principal {
    return this.storageCanisterId;
  }

  getKeyManagerCanisterId(): Principal {
    return this.keyManagerCanisterId;
  }

  async getViewPublicKey(address: Uint8Array): Promise<Uint8Array> {
    const actor = await this.getKeyManagerActor();
    const result = await actor.get_view_public_key(address);
    return unwrapResult(result, 'get_view_public_key');
  }

  async requestEncryptedViewKey(request: EncryptedViewKeyRequest): Promise<Uint8Array> {
    const actor = await this.getKeyManagerActor();
    const result = await actor.request_encrypted_view_key(toCandidEncryptedViewKeyRequest(request));
    return unwrapResult(result, 'request_encrypted_view_key');
  }

  async getMaxNonce(address: Uint8Array): Promise<bigint> {
    const actor = await this.getKeyManagerActor();
    const result = await actor.get_max_nonce(address);
    return unwrapResult(result, 'get_max_nonce');
  }

  async submitAnnouncement(input: AnnouncementInput): Promise<Announcement> {
    const actor = await this.getStorageActor();
    const candidAnnouncement = await actor.submit_announcement(toCandidAnnouncementInput(input));
    return mapAnnouncement(candidAnnouncement);
  }

  async listAnnouncements(startAfter?: bigint, limit?: number): Promise<AnnouncementPage> {
    const actor = await this.getStorageActor();
    const start = (startAfter === undefined ? [] : [startAfter]) as [] | [bigint];
    const cappedLimit = (limit === undefined ? [] : [limit]) as [] | [number];
    const page = await actor.list_announcements(start, cappedLimit);
    return {
      announcements: page.announcements.map(mapAnnouncement),
      nextId: page.next_id.length === 0 ? null : page.next_id[0],
    };
  }

  async getAnnouncement(id: bigint): Promise<Announcement | null> {
    const actor = await this.getStorageActor();
    const result = await actor.get_announcement(id);
    if (result.length === 0) {
      return null;
    }
    return mapAnnouncement(result[0]);
  }

  private async getKeyManagerActor(): Promise<KeyManagerActor> {
    if (this.keyManagerActor) {
      return this.keyManagerActor;
    }
    this.keyManagerActor = Actor.createActor<KeyManagerActor>(keyManagerIdlFactory, {
      agent: this.agent,
      canisterId: this.keyManagerCanisterId,
    });
    return this.keyManagerActor;
  }

  private async getStorageActor(): Promise<StorageActor> {
    if (this.storageActor) {
      return this.storageActor;
    }
    this.storageActor = Actor.createActor<StorageActor>(storageIdlFactory, {
      agent: this.agent,
      canisterId: this.storageCanisterId,
    });
    return this.storageActor;
  }
}

function unwrapResult<T>(result: CanisterResult<T>, method: string): T {
  if ('Ok' in result) {
    return result.Ok;
  }
  throw new StealthError(`${method} failed: ${result.Err}`);
}

function mapAnnouncement(announcement: AnnouncementCandid): Announcement {
  return {
    id: announcement.id,
    ibeCiphertext: announcement.ibe_ciphertext,
    ciphertext: announcement.ciphertext,
    nonce: announcement.nonce,
    createdAtNs: announcement.created_at_ns,
  };
}

function toCandidAnnouncementInput(input: AnnouncementInput): AnnouncementInputCandid {
  return {
    ibe_ciphertext: input.ibeCiphertext,
    ciphertext: input.ciphertext,
    nonce: input.nonce,
  };
}

function toCandidEncryptedViewKeyRequest(request: EncryptedViewKeyRequest): EncryptedViewKeyRequestCandid {
  return {
    address: request.address,
    transport_public_key: request.transportPublicKey,
    expiry_ns: request.expiryNs,
    nonce: request.nonce,
    signature: request.signature,
  };
}

const keyManagerIdlFactory: IDL.InterfaceFactory = ({ IDL: idl }) => {
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

const storageIdlFactory: IDL.InterfaceFactory = ({ IDL: idl }) => {
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
