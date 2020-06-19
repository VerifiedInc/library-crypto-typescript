import crypto from 'crypto';
import stringify from 'fast-json-stable-stringify';
import bs58 from 'bs58';

export function sign (data: any, privateKey: string): string {
  const stringifiedData = stringify(data);
  const buf = Buffer.from(stringifiedData);
  const hash = crypto.createHash('sha256');
  hash.update(buf);
  const signatureValueBuf = crypto.sign(null, hash.digest(), privateKey);
  return bs58.encode(signatureValueBuf);
}
