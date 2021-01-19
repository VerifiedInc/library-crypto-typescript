import { EncryptedData } from './types';
/**
 * @param {string} privateKey RSA private key (pem or base58) corresponding to the public key used for encryption
 * @param {EncryptedData} encryptedData EncryptedData object, like one returned from encrypt()
 *                                      contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                                      key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {object} the decrypted object
 */
export declare function decrypt(privateKey: string, encryptedData: EncryptedData, encoding?: 'base58' | 'pem'): unknown;
//# sourceMappingURL=decrypt.d.ts.map