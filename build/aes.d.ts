/// <reference types="node" />
/// <reference types="node" />
/**
 * Class to facilitate encryption and decryption of data using AES.
 * Note: that the IV attribute is not a class variable because it ought to be unique for each encrypt call for the same class instance (aka same key).
 */
export declare class Aes {
    key: Buffer;
    algorithm: string;
    constructor(key?: Buffer, algorithm?: string);
    /**
     * Encrypts input Uint8Array using AES.
     * @param data Uint8Array
     * @param iv Uint8Array
     * @returns Buffer
     */
    encrypt(data: Uint8Array, iv: Uint8Array): Buffer;
    /**
     * Decrypts input Uint8Array using AES.
     * @param data Uint8Array
     * @returns Buffer
     */
    decrypt(data: Uint8Array, iv: Uint8Array): Buffer;
    /**
     * Helper function to generate a random byte IV.
     * @returns Uint8Array
     */
    generateIv(bytes?: number): Uint8Array;
}
//# sourceMappingURL=aes.d.ts.map