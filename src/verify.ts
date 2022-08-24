import crypto from 'crypto';

import { decodeKey } from './helpers';
import { CryptoError } from './types/CryptoError';
import { PublicKeyInfo } from '@unumid/types';

/**
 * Used to verify a byte array. The new defacto verify function thanks to the property of Protobuf's ability to encode to bytes and decode back
 * an object in a deterministic fashion.
 *
 * @param {string} signature base58 signature, like one created with sign()
 * @param {Uint8Array} bytes byte array to verify
 * @param {PublicKeyInfo} publicKey PublicKeyInfo corresponding to the private key used to create the signature (pem or base58)
 * @returns {boolean} true if signature was created by signing data with the private key corresponding to publicKey
 */
export function verifyBytes (signature: string, bytes: Uint8Array, publicKey: PublicKeyInfo): boolean {
  if (!publicKey.publicKey) {
    throw new CryptoError('Public key is missing');
  }

  if (!publicKey.encoding) {
    throw new CryptoError('Public key encoding is missing');
  }

  return verifyBytesHelper(signature, bytes, publicKey.publicKey, publicKey.encoding);
}

/**
 * Helper used to verify a byte array. The new defacto verify function thanks to the property of Protobuf's ability to encode to bytes and decode back
 * an object in a deterministic fashion.
 *
 * @param {string} signature base58 signature, like one created with sign()
 * @param {Uint8Array} bytes byte array to verify
 * @param {string} publicKey public key corresponding to the private key used to create the signature (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {boolean} true if signature was created by signing data with the private key corresponding to publicKey
 */
export function verifyBytesHelper (signature: string, bytes: Uint8Array, publicKey: string, encoding: 'base58' | 'pem' = 'pem'): boolean {
  try {
    // decode public key if necessary
    const decodedPublicKey = decodeKey(publicKey, encoding);

    // decode signature from base58 to a Buffer
    const signatureBytes = Buffer.from(signature, 'base64');

    // if we pass the key to crypto.verify as a buffer, it will assume pem format
    // we need to convert it to a KeyObject first in order to use der formatted keys
    const format = encoding === 'pem' ? 'pem' : 'der';
    const type = encoding === 'pem' ? 'pkcs1' : 'spki';
    const publicKeyObj = crypto.createPublicKey({ key: decodedPublicKey, format, type });

    // verify the signature with the public key and return whether it succeeded
    const result = crypto.verify(null, bytes, publicKeyObj, signatureBytes);
    return result;
  } catch (e) {
    throw new CryptoError(e.message, e.code);
  }
}
