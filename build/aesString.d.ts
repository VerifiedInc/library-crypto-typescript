/// <reference types="node" />
/// <reference types="node" />
/**
 * Class to handle aes encryption and decryption with string inputs.
 */
export declare class AesString {
    key: Buffer;
    iv: Buffer;
    algorithm: string;
    constructor(key?: Buffer, iv?: Buffer, algorithm?: string);
    encrypt(data: Uint8Array): Buffer;
    decrypt(data: Uint8Array): Buffer;
}
//# sourceMappingURL=aesString.d.ts.map