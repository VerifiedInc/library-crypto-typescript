import { privateDecrypt } from 'crypto';
import bs58 from 'bs58';

export function decrypt (privateKey: string, encrypted: string): Record<string, unknown> {
  const encryptedBuf = bs58.decode(encrypted);
  const decryptedBuf = privateDecrypt(privateKey, encryptedBuf);
  const decryptedStr = decryptedBuf.toString();
  return JSON.parse(decryptedStr);
}
