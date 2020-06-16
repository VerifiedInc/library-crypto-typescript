import { publicEncrypt } from 'crypto';

import stringify from 'fast-json-stable-stringify';
import bs58 from 'bs58';

export function encrypt (publicKey: string, data: Record<string, unknown>): string {
  const stringifiedData = stringify(data);
  const dataBuf = Buffer.from(stringifiedData);
  const encryptedBuf = publicEncrypt(publicKey, dataBuf);
  return bs58.encode(encryptedBuf);
}
