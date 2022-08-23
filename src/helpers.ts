import { generateKeyPair } from 'crypto';
import { promisify } from 'util';
import bs58 from 'bs58';

export const promisifiedGenerateKeyPair = promisify(generateKeyPair);

export function decodeKey (publicKey: string, encoding: 'base58' | 'pem'): string | Buffer {
  return encoding === 'base58' ? bs58.decode(publicKey) : publicKey;
}

export function derToPem (key: Buffer | string, type: 'public' | 'private'): string {
  if (typeof key === 'string') {
    // it's already pem
    return key;
  }
  const bs64 = key.toString('base64');

  const header = `-----BEGIN ${type.toUpperCase()} KEY-----`;
  const footer = `-----END ${type.toUpperCase()} KEY-----`;

  return `${header}\n${bs64}\n${footer}`;
}
