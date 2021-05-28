/// <reference types="node" />
import { EncryptedData } from './types';
declare type BinaryLike = string | NodeJS.ArrayBufferView;
/**
 * @param {string} did the DID and key identifier fragment resolving to the public key
 * @param {string} publicKey RSA public key (pem or base58)
 * @param {object} data data to encrypt (JSON-serializable object)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {EncryptedData} contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                          key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 */
export declare function encrypt(did: string, publicKey: string, data: unknown, encoding?: 'base58' | 'pem'): EncryptedData;
/**
 * @param {string} did the DID and key identifier fragment resolving to the public key
 * @param {string} publicKey RSA public key (pem or base58)
 * @param {BinaryLike} data data to encrypt
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {EncryptedData} contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                          key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 */
export declare function encryptBytes(did: string, publicKey: string, data: BinaryLike, encoding?: 'base58' | 'pem'): EncryptedData;
export {};
//# sourceMappingURL=encrypt.d.ts.map