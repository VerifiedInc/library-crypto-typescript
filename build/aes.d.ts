/// <reference types="node" />
/// <reference types="node" />
/**
 * Class to facilitate encryption and decryption of data using AES.
 */
export declare class Aes {
    key: Buffer;
    iv: Buffer;
    algorithm: string;
    constructor(key?: Buffer, iv?: Buffer, algorithm?: string);
    /**
     * Encrypts input Uint8Array using AES.
     * @param data
     * @returns Buffer
     */
    encrypt(data: Uint8Array): Buffer;
    /**
     * Decrypts input Uint8Array using AES.
     * @param data
     * @returns Buffer
     */
    decrypt(data: Uint8Array): Buffer;
}
//# sourceMappingURL=aes.d.ts.map