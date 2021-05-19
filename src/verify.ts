import crypto from 'crypto';
import stringify from 'fast-json-stable-stringify';
import bs58 from 'bs58';

import { decodeKey } from './helpers';
import { CryptoError } from './types/CryptoError';

/**
 * Used to verify the provide data object against a provided Base58 encode signature.
 * Should only be used if dealing with projects can ensure identical data object string encoding.
 * For this reason it deprecated in favor of using protobufs for objects that need to be signed and leveraging signBytes.
 *
 * @param {string} signature base58 signature, like one created with sign()
 * @param {any} data data to verify (JSON-serializable object)
 * @param {string} publicKey public key corresponding to the private key used to create the signature (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {boolean} true if signature was created by signing data with the private key corresponding to publicKey
 */
export function verify (signature: string, data: unknown, publicKey: string, encoding: 'base58' | 'pem' = 'pem'): boolean {
  try {
    // serialize data as a deterministic JSON string
    const stringifiedData = stringify(data);
    return verifyString(signature, stringifiedData, publicKey, encoding);
  } catch (e) {
    throw new CryptoError(e.message, e.code);
  }
}

/**
 * Used to verify the provide data string against a provided Base58 encode signature.
 * A less than ideal situation of being handling a string representation of the signed object for reason of then having to convert back to the object.
 * For this reason it deprecated in favor of using protobufs for objects that need to be signed and leveraging signBytes.
 *
 * @param {string} signature base58 signature, like one created with sign()
 * @param {string} stringifiedData data (JSON-serializable object) as a string to verify
 * @param {string} publicKey public key corresponding to the private key used to create the signature (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {boolean} true if signature was created by signing data with the private key corresponding to publicKey
 */
export function verifyString (signature: string, stringifiedData: string, publicKey: string, encoding: 'base58' | 'pem' = 'pem'): boolean {
  try {
    // convert stringified data to a Buffer
    const dataBuf = Buffer.from(stringifiedData);

    // verifiy signature with the public key and return whether it succeeded
    return verifyBytes(signature, dataBuf, publicKey, encoding);
  } catch (e) {
    throw new CryptoError(e.message, e.code);
  }
}

/**
 * Used to verify a byte array. Exported thanks to the property of Protobuf's ability to encode to bytes and decode back
 * an object in a deterministic fashion.
 *
 * @param {string} signature base58 signature, like one created with sign()
 * @param {Buffer} bytes byte array to verify
 * @param {string} publicKey public key corresponding to the private key used to create the signature (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {boolean} true if signature was created by signing data with the private key corresponding to publicKey
 */
export function verifyBytes (signature: string, bytes: Buffer, publicKey: string, encoding: 'base58' | 'pem' = 'pem'): boolean {
  try {
    // decode public key if necessary
    const decodedPublicKey = decodeKey(publicKey, encoding);

    // decode signature from base58 to a Buffer
    const signatureBytes = bs58.decode(signature);

    // if we pass the key to crypto.verify as a buffer, it will assume pem format
    // we need to convert it to a KeyObject first in order to use der formatted keys
    const format = encoding === 'pem' ? 'pem' : 'der';
    const type = encoding === 'pem' ? 'pkcs1' : 'spki';
    const publicKeyObj = crypto.createPublicKey({ key: decodedPublicKey, format, type });

    // verifiy signature with the public key and return whether it succeeded
    const result = crypto.verify(null, bytes, publicKeyObj, signatureBytes);
    return result;
  } catch (e) {
    throw new CryptoError(e.message, e.code);
  }
}
