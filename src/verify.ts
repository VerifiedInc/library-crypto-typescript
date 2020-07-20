import crypto from 'crypto';
import stringify from 'fast-json-stable-stringify';
import bs58 from 'bs58';

/**
 * @param {string} signature base58 signature, like one created with sign()
 * @param {any} data data to verify (JSON-serializable object)
 * @param {string} publicKey public key corresponding to the private key used to create the signature (pem or der)
 * @returns {boolean} true if signature was created by signing data with the private key corresponding to publicKey
 */
export function verify (signature: string, data: any, publicKey: string): boolean {
  // serialize data as a deterministic JSON string
  const stringifiedData = stringify(data);

  // convert stringified data to a Buffer
  const dataBuf = Buffer.from(stringifiedData);

  // decode signature from base58 to a Buffer
  const signatureBuf = bs58.decode(signature);

  // verifiy signature with the public key and return whether it succeeded
  const result = crypto.verify(null, dataBuf, publicKey, signatureBuf);
  return result;
}
