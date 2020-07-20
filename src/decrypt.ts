import { privateDecrypt, createDecipheriv } from 'crypto';
import bs58 from 'bs58';
import { EncryptedData } from './types';

export function decrypt (privateKey: string, encryptedData: EncryptedData): any {
  const { data } = encryptedData;
  const { iv, key, algorithm } = encryptedData.key;

  // decode aes key info and encrypted data from base58 to Buffers
  const decodedEncryptedIv = bs58.decode(iv);
  const decodedEncryptedKey = bs58.decode(key);
  const decodedEncryptedAlgorithm = bs58.decode(algorithm);
  const decodedEncryptedData = bs58.decode(data);

  // decrypt aes key info with private key
  const decryptedIv = privateDecrypt(privateKey, decodedEncryptedIv);
  const decryptedKey = privateDecrypt(privateKey, decodedEncryptedKey);
  const decryptedAlgorithm = privateDecrypt(privateKey, decodedEncryptedAlgorithm);

  // create aes key
  const decipher = createDecipheriv(decryptedAlgorithm.toString(), decryptedKey, decryptedIv);

  // decrypt data with aes key
  const decrypted1 = decipher.update(decodedEncryptedData);
  const decrypted2 = decipher.final();
  const decrypted = Buffer.concat([decrypted1, decrypted2]);

  // re-encode decrypted data as a regular utf-8 string
  const decryptedStr = decrypted.toString('utf-8');

  // parse original encoded object from decrypted json string
  return JSON.parse(decryptedStr);
}
