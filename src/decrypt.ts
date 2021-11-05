import { privateDecrypt, createDecipheriv } from 'crypto';
import bs58 from 'bs58';

import { EncryptedData, EncryptedKey, RSAPadding } from '@unumid/types';
import { decodeKey, derToPem } from './helpers';
import { CryptoError } from './types/CryptoError';
import { getPadding } from './utils';

/**
 * Used to encode the provided data object into a string after decrypting.
 * Should only be used if dealing with projects can ensure identical data object string encoding.
 * For this reason it deprecated in favor of decryptBytes with Protobufs for objects that need to be encrypted and decrypted.
 *
 * @param {string} privateKey RSA private key (pem or base58) corresponding to the public key used for encryption
 * @param {EncryptedData} encryptedData EncryptedData object, like one returned from encrypt()
 *                                      contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                                      key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {object} the decrypted object
 */
export function decrypt (privateKey: string, encryptedData: EncryptedData, encoding: 'base58' | 'pem' = 'pem'): unknown {
  try {
    const decrypted: Buffer = decryptBytes(privateKey, encryptedData, encoding);

    // re-encode decrypted data as a regular utf-8 string
    const decryptedStr = decrypted.toString('utf-8');

    // parse original encoded object from decrypted json string
    return JSON.parse(decryptedStr);
  } catch (e) {
    const cryptoError = e as CryptoError;
    throw new CryptoError(cryptoError.message, cryptoError.code);
  }
}

/**
 * Used to decrypt a byte array. Exposed for use with Protobuf's byte arrays.
 *
 * @param {string} privateKey RSA private key (pem or base58) corresponding to the public key used for encryption
 * @param {EncryptedData} encryptedData EncryptedData object, like one returned from encrypt()
 *                                      contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                                      key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {object} the decrypted object
 */
export function decryptBytes (privateKey: string, encryptedData: EncryptedData, encoding: 'base58' | 'pem' = 'pem'): Buffer {
  try {
    const { data } = encryptedData;
    const { iv, key, algorithm } = (encryptedData.key as EncryptedKey);

    // decode the private key, if necessary
    const decodedPrivateKey = decodeKey(privateKey, encoding);

    // node can only decrypt with pem-encoded keys
    const privateKeyPem = derToPem(decodedPrivateKey, 'private');

    // decode aes key info and encrypted data from base58 to Buffers
    const decodedEncryptedIv = bs58.decode(iv);
    const decodedEncryptedKey = bs58.decode(key);
    const decodedEncryptedAlgorithm = bs58.decode(algorithm);
    const decodedEncryptedData = bs58.decode(data);

    // we need to use a key object to set non-default padding
    // for interoperability with android/ios/webcrypto cryptography implementations
    const privateKeyObj = {
      key: privateKeyPem,
      padding: getPadding(encryptedData.rsaPadding || RSAPadding.PKCS)
    };

    // decrypt aes key info with private key
    const decryptedIv = privateDecrypt(privateKeyObj, decodedEncryptedIv);
    const decryptedKey = privateDecrypt(privateKeyObj, decodedEncryptedKey);
    const decryptedAlgorithm = privateDecrypt(privateKeyObj, decodedEncryptedAlgorithm);

    // create aes key
    const decipher = createDecipheriv(decryptedAlgorithm.toString(), decryptedKey, decryptedIv);

    // decrypt data with aes key
    const decrypted1 = decipher.update(decodedEncryptedData);
    const decrypted2 = decipher.final();
    const decrypted = Buffer.concat([decrypted1, decrypted2]);

    return decrypted;
  } catch (e) {
    const cryptoError = e as CryptoError;
    throw new CryptoError(cryptoError.message, cryptoError.code);
  }
}
