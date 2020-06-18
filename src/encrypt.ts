import { publicEncrypt, randomBytes, createCipheriv } from 'crypto';

import stringify from 'fast-json-stable-stringify';
import bs58 from 'bs58';

import { EncryptedData } from './types';

export function encrypt (did: string, publicKey: string, data: Record<string, unknown>): EncryptedData {
  const stringifiedData = stringify(data);

  // create aes key
  const key = randomBytes(32);
  const iv = randomBytes(16);
  const algorithm = 'aes-256-cbc';
  const cipher = createCipheriv(algorithm, key, iv);

  // encrypt data with aes key
  cipher.update(stringifiedData);
  const encrypted = cipher.final();

  // encrypt aes key with public key
  const encryptedIv = publicEncrypt(publicKey, iv);
  const encryptedKey = publicEncrypt(publicKey, key);
  const encryptedAlgo = publicEncrypt(publicKey, Buffer.from(algorithm));
  return {
    data: bs58.encode(encrypted),
    key: {
      iv: bs58.encode(encryptedIv),
      key: bs58.encode(encryptedKey),
      algorithm: bs58.encode(encryptedAlgo),
      did
    }
  };
}
