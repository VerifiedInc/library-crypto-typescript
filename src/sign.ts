import crypto from 'crypto';
import stringify from 'fast-json-stable-stringify';
import bs58 from 'bs58';

export function sign (data: any, privateKey: string): string {
  const stringifiedData = stringify(data);
  const buf = Buffer.from(stringifiedData);
  const signatureValueBuf = crypto.sign(null, buf, privateKey);
  return bs58.encode(signatureValueBuf);
}
