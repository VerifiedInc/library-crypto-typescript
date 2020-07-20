import crypto from 'crypto';
import stringify from 'fast-json-stable-stringify';
import bs58 from 'bs58';

/**
 * @param {*} data data to sign (JSON-serializable object)
 * @param {string} privateKey private key to sign with (pem or der)
 * @returns {string} signature with privateKey over data encoded as a base58 string
 */
export function sign (data: any, privateKey: string): string {
  // serialize data as a deterministic JSON string
  const stringifiedData = stringify(data);

  // convert to a Buffer and sign with private key
  const buf = Buffer.from(stringifiedData);
  const signatureValueBuf = crypto.sign(null, buf, privateKey);

  // return resulting Buffer encoded as a base58 string
  return bs58.encode(signatureValueBuf);
}
