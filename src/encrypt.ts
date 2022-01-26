import { publicEncrypt, randomBytes, createCipheriv, constants } from 'crypto';

import stringify from 'fast-json-stable-stringify';
import bs58 from 'bs58';

import { EncryptedData, RSAPadding } from '@unumid/types';
import { decodeKey, derToPem } from './helpers';
import { CryptoError } from './types/CryptoError';
import { getPadding } from './utils';
import { PublicKeyInfo } from '@unumid/types/build/protos/crypto';

// from node.crypto lib
type BinaryLike = string | NodeJS.ArrayBufferView;

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
export function encrypt (
  did: string,
  publicKey: string,
  data: unknown,
  encoding: 'base58' | 'pem' = 'pem',
  rsaPadding: RSAPadding = RSAPadding.PKCS
): EncryptedData {
  try {
    // serialize data as a deterministic JSON string
    const stringifiedData = stringify(data);

    return encryptBytes(did, publicKey, stringifiedData, encoding, rsaPadding);
  } catch (e) {
    const cryptoError = e as CryptoError;
    throw new CryptoError(cryptoError.message, cryptoError.code);
  }
}

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
export function encryptBytes (
  did: string,
  publicKey: string,
  data: BinaryLike,
  encoding: 'base58' | 'pem' = 'pem',
  rsaPadding: RSAPadding = RSAPadding.PKCS
): EncryptedData {
  try {
    // decode the public key, if necessary
    const decodedPublicKey = decodeKey(publicKey, encoding);

    // node can only encrypt with pem-encoded keys
    const publicKeyPem = derToPem(decodedPublicKey, 'public');

    // create aes key for encryption
    const key = randomBytes(32);
    const iv = randomBytes(16);
    const algorithm = 'aes-256-cbc';
    const cipher = createCipheriv(algorithm, key, iv);

    // encrypt data with aes key
    const encrypted1 = cipher.update(data);
    const encrypted2 = cipher.final();
    const encrypted = Buffer.concat([encrypted1, encrypted2]);

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
      data: bs58.encode(encrypted),
      key: {
        iv: bs58.encode(encryptedIv),
        key: bs58.encode(encryptedKey),
        algorithm: bs58.encode(encryptedAlgo),
        did
      },
      rsaPadding
    };
  } catch (e) {
    const cryptoError = e as CryptoError;
    throw new CryptoError(cryptoError.message, cryptoError.code);
  }
}

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
export function encryptBytesV2 (
  did: string,
  publicKey: PublicKeyInfo,
  data: BinaryLike,
  rsaPadding: RSAPadding = RSAPadding.PKCS
): EncryptedData {
  if (!publicKey.publicKey) {
    throw new CryptoError('Public key is missing');
  }

  if (!publicKey.encoding) {
    throw new CryptoError('Public key encoding is missing');
  }

  return encryptBytes(did, publicKey.publicKey, data, publicKey.encoding as 'base58' | 'pem', rsaPadding);
}
