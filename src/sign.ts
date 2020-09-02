import crypto from 'crypto';
import stringify from 'fast-json-stable-stringify';
import bs58 from 'bs58';

import { decodeKey } from './helpers';

/**
 * @param {*} data data to sign (JSON-serializable object)
 * @param {string} privateKey private key to sign with (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {string} signature with privateKey over data encoded as a base58 string
 */
export function sign (data: unknown, privateKey: string, encoding: 'base58' | 'pem' = 'pem'): string {
  // serialize data as a deterministic JSON string
  const stringifiedData = stringify(data);

  const decodedPrivateKey = decodeKey(privateKey, encoding);

  // convert to a Buffer and sign with private key
  const buf = Buffer.from(stringifiedData);
  const signatureValueBuf = crypto.sign(null, buf, decodedPrivateKey);

  // return resulting Buffer encoded as a base58 string
  return bs58.encode(signatureValueBuf);
}
