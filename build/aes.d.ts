/// <reference types="node" />
export declare class Aes {
    key: Buffer;
    iv: Buffer;
    algorithm: string;
    constructor(key?: Buffer, iv?: Buffer, algorithm?: string);
    encrypt(data: Uint8Array): Buffer;
    decrypt(data: Uint8Array): Buffer;
}
//# sourceMappingURL=aes.d.ts.map