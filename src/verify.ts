import crypto from 'crypto';
import stringify from 'fast-json-stable-stringify';
import bs58 from 'bs58';

export function verify (signature: string, data: any, publicKey: string): boolean {
  const stringifiedData = stringify(data);
  const dataBuf = Buffer.from(stringifiedData);
  const signatureBuf = bs58.decode(signature);
  const result = crypto.verify(null, dataBuf, publicKey, signatureBuf);
  return result;
}
