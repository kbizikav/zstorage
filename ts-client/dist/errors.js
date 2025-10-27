export class StealthError extends Error {
    constructor(message) {
        super(message);
        this.name = 'StealthError';
    }
}
export class AnnouncementIgnoredError extends StealthError {
    constructor(reason) {
        super(`announcement ignored: ${reason}`);
        this.name = 'AnnouncementIgnoredError';
    }
}
