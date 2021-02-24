import crypto from 'crypto';
import { CryptoError } from './types/CryptoError';
import { decodeKey } from './helpers';

/**
 * @param {string} key key (pem or base58)
 * @param {string} encoding the encoding used for the key ('base58' or 'pem', default 'pem')
 * @returns {boolean} true if valid key information
 */
export function validatePublicKey (key: string, encoding: 'base58' | 'pem' = 'pem'): boolean {
  // decode public key if necessary
  const decodedKey = decodeKey(key, encoding);

  // if we pass the key to crypto.verify as a buffer, it will assume pem format
  // we need to convert it to a KeyObject first in order to use der formatted keys
  const format = encoding === 'pem' ? 'pem' : 'der';
  const type = encoding === 'pem' ? 'pkcs1' : 'spki';

  try {
    crypto.createPublicKey({ key: decodedKey, format, type });
  } catch (e) {
    throw new CryptoError(e.message, e.code);
  }

  // an exception would be thrown if invalid
  return true;
}
