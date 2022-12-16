import { publicEncrypt, randomBytes, createCipheriv } from 'crypto';

import { EncryptedData, RSAPadding } from '@unumid/types';
import { decodeKey, derToPem } from './helpers';
import { CryptoError } from './types/CryptoError';
import { getPadding } from './utils';
import { PublicKeyInfo } from '@unumid/types/build/protos/crypto';
import { Aes } from './aes';

/**
 *  Used to encrypt a byte array. Exposed for use with Protobuf's byte arrays.
 *
 * @param {string} did the DID and key identifier fragment resolving to the public key
 * @param {PublicKeyInfo} publicKey RSA publicKeyInfo
 * @param {BinaryLike} data data to encrypt
 * @returns {EncryptedData} contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                          key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 */
export function encryptBytes (
  did: string,
  publicKeyInfo: PublicKeyInfo,
  data: Uint8Array
): EncryptedData {
  const { publicKey, encoding, rsaPadding } = publicKeyInfo;

  if (!publicKey) {
    throw new CryptoError('Public key is missing');
  }

  // checking even though a default value is in the helper because all PublicKeyInfo objects ought to have it set
  if (!encoding) {
    throw new CryptoError('Public key encoding is missing');
  }

  return encryptBytesHelper(did, publicKey, data, encoding as 'base58' | 'pem', rsaPadding);
}

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
export function encryptBytesHelper (
  did: string,
  publicKey: string,
  data: Uint8Array,
  encoding: 'base58' | 'pem' = 'pem',
  rsaPadding: RSAPadding = RSAPadding.PKCS
): EncryptedData {
  try {
    // decode the public key, if necessary
    const decodedPublicKey = decodeKey(publicKey, encoding);

    // node can only encrypt with pem-encoded keys
    const publicKeyPem = derToPem(decodedPublicKey, 'public');

    // // create aes key for encryption
    // const key = randomBytes(32);
    // const iv = randomBytes(16);
    // const algorithm = 'aes-256-cbc';
    // const cipher = createCipheriv(algorithm, key, iv);

    // // encrypt data with aes key
    // const encrypted1 = cipher.update(data);
    // const encrypted2 = cipher.final();
    // const encrypted = Buffer.concat([encrypted1, encrypted2]);

    // const { key, iv, algorithm, encrypted } = aesEncryption(data);

    // create aes key, iv and Aes instance for encryption
    const key = randomBytes(32);
    const iv = randomBytes(16);
    const algorithm = 'aes-256-cbc';
    const aes = new Aes(key, iv, algorithm);

    // encrypt data with aes key
    const encrypted = aes.encrypt(data);

    // we need to use a key object to set non-default padding
    // for interoperability with android/ios/webcrypto cryptography implementations
    const publicKeyObj = {
      key: publicKeyPem,
      padding: getPadding(rsaPadding)
    };

    // encrypt aes key with public key
    const encryptedIv = publicEncrypt(publicKeyObj, iv);
    const encryptedKey = publicEncrypt(publicKeyObj, key);
    const encryptedAlgo = publicEncrypt(publicKeyObj, Buffer.from(algorithm));

    // return EncryptedData object with encrypted data and aes key info
    return {
      data: encrypted.toString('base64'),
      key: {
        iv: encryptedIv.toString('base64'),
        key: encryptedKey.toString('base64'),
        algorithm: encryptedAlgo.toString('base64'),
        did
      },
      rsaPadding
    };
  } catch (e) {
    const cryptoError = e as CryptoError;
    throw new CryptoError(cryptoError.message, cryptoError.code);
  }
}

// /**
//  * Function used to encrypt a byte array with aes.
//  * @returns
//  */
// export function aesEncryption (data: Uint8Array): {key: Buffer, iv: Buffer, algorithm: string, encrypted: Buffer} {
//   // create aes key for encryption
//   const key = randomBytes(32);
//   const iv = randomBytes(16);
//   const algorithm = 'aes-256-cbc';
//   // const cipher = createCipheriv(algorithm, key, iv);
//   // return aesEncryptionHelper(data, key);
//   const aes = new Aes(key, iv, algorithm);

//   // encrypt data with aes key
//   const encrypted = aes.encrypt(data);
// }

// export function aesEncryptionHelper (data: Uint8Array, key: Buffer): {key: Buffer, iv: Buffer, algorithm: string, encrypted: Buffer} {
//   // create aes iv for encryption
//   const iv = randomBytes(16);
//   const algorithm = 'aes-256-cbc';
//   const cipher = createCipheriv(algorithm, key, iv);

//   // encrypt data with aes key
//   const encrypted1 = cipher.update(data);
//   const encrypted2 = cipher.final();
//   const encrypted = Buffer.concat([encrypted1, encrypted2]);

//   return {
//     key,
//     iv,
//     algorithm,
//     encrypted
//   };
// }
