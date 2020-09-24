import crypto from 'crypto';
import stringify from 'fast-json-stable-stringify';
import bs58 from 'bs58';

import { decodeKey } from './helpers';
/**
 * @param {string} signature base58 signature, like one created with sign()
 * @param {any} data data to verify (JSON-serializable object)
 * @param {string} publicKey public key corresponding to the private key used to create the signature (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {boolean} true if signature was created by signing data with the private key corresponding to publicKey
 */
export function verify (signature: string, data: unknown, publicKey: string, encoding: 'base58' | 'pem' = 'pem'): boolean {
  // serialize data as a deterministic JSON string
  const stringifiedData = stringify(data);

  // decode public key if necessary
  const decodedPublicKey = decodeKey(publicKey, encoding);

  // convert stringified data to a Buffer
  const dataBuf = Buffer.from(stringifiedData);

  // decode signature from base58 to a Buffer
  const signatureBuf = bs58.decode(signature);

  // if we pass the key to crypto.verify as a buffer, it will assume pem format
  // we need to convert it to a KeyObject first in order to use der formatted keys
  const format = encoding === 'pem' ? 'pem' : 'der';
  const type = encoding === 'pem' ? 'pkcs1' : 'spki';
  const publicKeyObj = crypto.createPublicKey({ key: decodedPublicKey, format, type });

  // verifiy signature with the public key and return whether it succeeded
  const result = crypto.verify(null, dataBuf, publicKeyObj, signatureBuf);
  return result;
}
