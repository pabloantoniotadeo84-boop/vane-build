import type { AttestationRecord, KeyPair } from '../crypto/types.js';
export declare class Store {
    private readonly db;
    constructor(path?: string);
    getKeys(): KeyPair | null;
    saveKeys(keys: KeyPair): void;
    getAllRecords(): AttestationRecord[];
    insertRecord(record: AttestationRecord): void;
}
//# sourceMappingURL=store.d.ts.map