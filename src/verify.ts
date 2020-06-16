import crypto from 'crypto';
import stringify from 'fast-json-stable-stringify';
import bs58 from 'bs58';

export function verify (signature: string, data: Record<string, unknown>, publicKey: string): boolean {
  const hash = crypto.createHash('sha256');
  const stringifiedData = stringify(data);
  const dataBuf = Buffer.from(stringifiedData);
  hash.update(dataBuf);
  const signatureBuf = bs58.decode(signature);
  const result = crypto.verify(null, hash.digest(), publicKey, signatureBuf);
  return result;
}
