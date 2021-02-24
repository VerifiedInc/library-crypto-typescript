import crypto from 'crypto';
import stringify from 'fast-json-stable-stringify';
import bs58 from 'bs58';

import { decodeKey } from './helpers';
import { CryptoError } from './types/CryptoError';

/**
 * @param {*} data data to sign (JSON-serializable object)
 * @param {string} privateKey private key to sign with (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {string} signature with privateKey over data encoded as a base58 string
 */
export function sign (data: unknown, privateKey: string, encoding: 'base58' | 'pem' = 'pem'): string {
  try {
    // serialize data as a deterministic JSON string
    const stringifiedData = stringify(data);

    const decodedPrivateKey = decodeKey(privateKey, encoding);

    // convert to a Buffer and sign with private key
    const buf = Buffer.from(stringifiedData);

    // if we pass the key to crypto.sign as a buffer, it will assume pem format
    // we need to convert it to a KeyObject first in order to use der formatted keys
    const format = encoding === 'pem' ? 'pem' : 'der';
    const type = encoding === 'pem' ? 'pkcs1' : 'pkcs8';

    const privateKeyObj = crypto.createPrivateKey({ key: decodedPrivateKey, format, type });
    const signatureValueBuf = crypto.sign(null, buf, privateKeyObj);

    // return resulting Buffer encoded as a base58 string
    return bs58.encode(signatureValueBuf);
  } catch (e) {
    throw new CryptoError(e.message, e.code);
  }
}
