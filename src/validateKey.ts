import crypto from 'crypto';
import { decodeKey } from './helpers';

/**
 * @param {string} key key (pem or base58)
 * @param {string} encoding the encoding used for the key ('base58' or 'pem', default 'pem')
 * @returns {boolean} true if valid key information
 */
export function validatePublicKeyInfo (key: string, encoding: 'base58' | 'pem' = 'pem'): boolean {
  // decode public key if necessary
  const decodedKey = decodeKey(key, encoding);

  // if we pass the key to crypto.verify as a buffer, it will assume pem format
  // we need to convert it to a KeyObject first in order to use der formatted keys
  const format = encoding === 'pem' ? 'pem' : 'der';
  const type = encoding === 'pem' ? 'pkcs1' : 'spki';
  crypto.createPublicKey({ key: decodedKey, format, type });

  // an exception would be thrown if invalid
  return true;
}
