/// <reference types="node" />
/// <reference types="node" />
import { EncryptedData } from '@unumid/types';
/**
 * Used to decrypt a byte array. Exposed for use with Protobuf's byte arrays.
 *
 * @param {string} privateKey RSA private key (pem or base58) corresponding to the public key used for encryption
 * @param {EncryptedData} encryptedData EncryptedData object, like one returned from encrypt()
 *                                      contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                                      key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 * @returns {object} the decrypted object
 */
export declare function decryptBytes(privateKey: string, encryptedData: EncryptedData): Buffer;
//# sourceMappingURL=decrypt.d.ts.map