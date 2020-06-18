import { privateDecrypt, createDecipheriv } from 'crypto';
import bs58 from 'bs58';
import { EncryptedData } from './types';

export function decrypt (privateKey: string, encryptedData: EncryptedData): Record<string, unknown> {
  // decode aes key info
  const { iv, key, algorithm } = encryptedData.key;

  const encryptedIv = bs58.decode(iv);
  const encryptedKey = bs58.decode(key);
  const encryptedAlgorithm = bs58.decode(algorithm);

  const decryptedIv = privateDecrypt(privateKey, encryptedIv);
  const decryptedKey = privateDecrypt(privateKey, encryptedKey);
  const decryptedAlgorithm = privateDecrypt(privateKey, encryptedAlgorithm);

  // create aes key
  const decipher = createDecipheriv(decryptedAlgorithm.toString(), decryptedKey, decryptedIv);

  // decrypt data with aes key
  decipher.update(bs58.decode(encryptedData.data));
  const decryptedStr = decipher.final('utf8');
  return JSON.parse(decryptedStr);
}
