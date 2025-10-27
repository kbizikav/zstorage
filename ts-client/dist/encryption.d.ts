import { VetKey } from '@dfinity/vetkeys';
import { Announcement, AnnouncementInput, DecryptedAnnouncement } from './types';
export interface EncryptPayloadOptions {
    identity?: Uint8Array;
    seed?: Uint8Array;
    randomBytes?: (length: number) => Uint8Array;
}
export declare function encryptAnnouncement(viewPublicKey: Uint8Array, plaintext: Uint8Array | string, options?: EncryptPayloadOptions): Promise<AnnouncementInput>;
export declare function encryptAnnouncementWithArtifacts(viewPublicKey: Uint8Array, plaintextInput: Uint8Array | string, options?: EncryptPayloadOptions): Promise<{
    announcement: AnnouncementInput;
    sessionKey: Uint8Array;
}>;
export declare function decryptAnnouncement(vetKey: VetKey, announcement: Announcement): Promise<DecryptedAnnouncement>;
export declare function scanAnnouncements(vetKey: VetKey, announcements: Announcement[]): Promise<DecryptedAnnouncement[]>;
//# sourceMappingURL=encryption.d.ts.map