import crypto from 'crypto';
import stringify from 'fast-json-stable-stringify';
import bs58 from 'bs58';

import { decodeKey } from './helpers';
import { CryptoError } from './types/CryptoError';

/**
 * @deprecated prefer signBytes
 * Used to encode the provided data object into a string prior to signing.
 * Should only be used if dealing with projects can ensure identical data object string encoding.
 * For this reason it deprecated in favor of signBytes for Protobufs for objects that need to be signed and verified.
 *
 * @param {*} data data to sign (JSON-serializable object)
 * @param {string} privateKey private key to sign with (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {string} signature with privateKey over data encoded as a base58 string
 */
export function sign (data: unknown, privateKey: string, encoding: 'base58' | 'pem' = 'pem'): string {
  try {
    // serialize data as a deterministic JSON string
    const stringifiedData = stringify(data);

    // convert to a Buffer and sign with private key
    const buf = Buffer.from(stringifiedData);

    // return resulting Buffer encoded as a base58 string
    return _signBytes(buf, privateKey, encoding);
  } catch (e) {
    throw new CryptoError(e.message, e.code);
  }
}

/**
 * Used to sign a byte array. Exported thanks to the property of Protobuf's ability to encode to bytes and decode back
 * an object in a deterministic fashion.
 *
 * @param {Uint8Array} bytes bytes array to sign
 * @param {string} privateKey private key to sign with (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {string} signature with privateKey over data encoded as a base58 string
 */
function _signBytes (bytes: Uint8Array, privateKey: string, encoding: 'base58' | 'pem' = 'pem'): string {
  try {
    const decodedPrivateKey = decodeKey(privateKey, encoding);

    // if we pass the key to crypto.sign as a buffer, it will assume pem format
    // we need to convert it to a KeyObject first in order to use der formatted keys
    const format = encoding === 'pem' ? 'pem' : 'der';
    const type = encoding === 'pem' ? 'pkcs1' : 'pkcs8';

    const privateKeyObj = crypto.createPrivateKey({ key: decodedPrivateKey, format, type });
    const signatureValueBuf = crypto.sign(null, bytes, privateKeyObj);

    // return resulting Buffer encoded as a base58 string
    return bs58.encode(signatureValueBuf);
  } catch (e) {
    throw new CryptoError(e.message, e.code);
  }
}

/**
 * Used to sign a byte array. Exported thanks to the property of Protobuf's ability to encode to bytes and decode back
 * an object in a deterministic fashion.
 *
 * @param {Uint8Array} bytes bytes array to sign
 * @param {string} privateKey private key to sign with (pem or base58)
 * @returns {string} signature with privateKey over data encoded as a base58 string
 */
export function signBytes (bytes: Uint8Array, privateKey: string): string {
  if (!privateKey) {
    throw new CryptoError('Private key is missing');
  }

  let encoding: 'base58' | 'pem' = 'base58';

  if (privateKey.includes('PRIVATE KEY')) {
    encoding = 'pem';
  }

  return _signBytes(bytes, privateKey, encoding);
}
