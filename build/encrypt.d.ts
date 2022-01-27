/// <reference types="node" />
import { EncryptedData, RSAPadding } from '@unumid/types';
import { PublicKeyInfo } from '@unumid/types/build/protos/crypto';
declare type BinaryLike = string | NodeJS.ArrayBufferView;
/**
 * @deprecated prefer encryptBytes
 * Used to encode the provided data object into a string prior to encrypting.
 * Should only be used if dealing with projects can ensure identical data object string encoding.
 * For this reason it deprecated in favor of encryptBytes with Protobufs for objects that need to be encrypted.
 *
 * @param {string} did the DID and key identifier fragment resolving to the public key
 * @param {string} publicKey RSA public key (pem or base58)
 * @param {object} data data to encrypt (JSON-serializable object)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @param { RSAPadding} rsaPadding padding to use for RSA encryption (PKCS1 v1.5 or OAEP).
 *                                 Necessary because web crypto only supports OAEP padding for decryption,
 *                                 and cannot decrypt data encrypted with PKCS1 v1.5 padding.
 *                                 Defaults to PKCS to preserve backwards compatibility,
 *                                 as older public keys (from before we used web crypto) do not specify a padding.
 * @returns {EncryptedData} contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                          key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 */
export declare function encrypt(did: string, publicKey: string, data: unknown, encoding?: 'base58' | 'pem', rsaPadding?: RSAPadding): EncryptedData;
/**
 *  Used to encrypt a byte array. Exposed for use with Protobuf's byte arrays.
 *
 * @param {string} did the DID and key identifier fragment resolving to the public key
 * @param {string} publicKey RSA public key (pem or base58)
 * @param {BinaryLike} data data to encrypt
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {EncryptedData} contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                          key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 */
export declare function _encryptBytes(did: string, publicKey: string, data: BinaryLike, encoding?: 'base58' | 'pem', rsaPadding?: RSAPadding): EncryptedData;
/**
 *  Used to encrypt a byte array. Exposed for use with Protobuf's byte arrays.
 *
 * @param {string} did the DID and key identifier fragment resolving to the public key
 * @param {PublicKeyInfo} publicKey RSA publicKeyInfo
 * @param {BinaryLike} data data to encrypt
 * @returns {EncryptedData} contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                          key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 */
export declare function encryptBytes(did: string, publicKeyInfo: PublicKeyInfo, data: BinaryLike): EncryptedData;
export {};
//# sourceMappingURL=encrypt.d.ts.map