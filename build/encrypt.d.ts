import { EncryptedData, RSAPadding } from '@unumid/types';
import { PublicKeyInfo } from '@unumid/types/build/protos/crypto';
/**
 *  Used to encrypt a byte array. Exposed for use with Protobuf's byte arrays.
 *
 * @param {string} did the DID and key identifier fragment resolving to the public key
 * @param {PublicKeyInfo} publicKey RSA publicKeyInfo
 * @param {BinaryLike} data data to encrypt
 * @returns {EncryptedData} contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                          key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 */
export declare function encryptBytes(did: string, publicKeyInfo: PublicKeyInfo, data: Uint8Array): EncryptedData;
/**
 *  Helper used to encrypt a byte array. Exposed for use with Protobuf's byte arrays.
 *
 * @param {string} did the DID and key identifier fragment resolving to the public key
 * @param {string} publicKey RSA public key (pem or base58)
 * @param {BinaryLike} data data to encrypt
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {EncryptedData} contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                          key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 */
export declare function encryptBytesHelper(did: string, publicKey: string, data: Uint8Array, encoding?: 'base58' | 'pem', rsaPadding?: RSAPadding): EncryptedData;
//# sourceMappingURL=encrypt.d.ts.map