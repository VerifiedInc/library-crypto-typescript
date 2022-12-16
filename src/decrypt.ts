import { privateDecrypt, createDecipheriv } from 'crypto';
import bs58 from 'bs58';

import { EncryptedData, EncryptedKey, RSAPadding } from '@unumid/types';
import { decodeKey, derToPem } from './helpers';
import { CryptoError } from './types/CryptoError';
import { detectEncodingType, getPadding } from './utils';
import { Aes } from './aes';

/**
 * Used to decrypt a byte array. Exposed for use with Protobuf's byte arrays.
 *
 * @param {string} privateKey RSA private key (pem or base58) corresponding to the public key used for encryption
 * @param {EncryptedData} encryptedData EncryptedData object, like one returned from encrypt()
 *                                      contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                                      key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 * @returns {object} the decrypted object
 */
export function decryptBytes (privateKey: string, encryptedData: EncryptedData): Buffer {
  if (!privateKey) {
    throw new CryptoError('Private key is missing');
  }

  // detect key encoding type
  const encoding = detectEncodingType(privateKey);

  return _decryptBytes(privateKey, encryptedData, encoding);
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
function _decryptBytes (privateKey: string, encryptedData: EncryptedData, encoding: 'base58' | 'pem' = 'pem'): Buffer {
  try {
    const { data } = encryptedData;
    const { iv, key, algorithm } = (encryptedData.key as EncryptedKey);

    // decode the private key, if necessary
    const decodedPrivateKey = decodeKey(privateKey, encoding);

    // node can only decrypt with pem-encoded keys
    const privateKeyPem = derToPem(decodedPrivateKey, 'private');

    // decode aes key info and encrypted data from base64 to Buffers
    const decodedEncryptedIv = Buffer.from(iv, 'base64');
    const decodedEncryptedKey = Buffer.from(key, 'base64');
    const decodedEncryptedAlgorithm = Buffer.from(algorithm, 'base64');
    const decodedEncryptedData = Buffer.from(data, 'base64');

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

    // create aes instance with decrypted aes key, iv, and algorithm
    const aes = new Aes(decryptedKey, decryptedIv, decryptedAlgorithm.toString());

    // decrypt data with aes
    const decrypted = aes.decrypt(decodedEncryptedData);

    return decrypted;
  } catch (e) {
    const cryptoError = e as CryptoError;
    throw new CryptoError(cryptoError.message, cryptoError.code);
  }
}
