import { generateKeyPair } from 'crypto';
import { promisify } from 'util';
import bs58 from 'bs58';

export const promisifiedGenerateKeyPair = promisify(generateKeyPair);

export function decodeKey (publicKey: string, encoding: 'base58' | 'pem'): string | Buffer {
  return encoding === 'base58' ? bs58.decode(publicKey) : publicKey;
}

export function derToPem (key: Buffer | string, type: 'public' | 'private', algorithm: 'rsa' | 'ec'): string {
  if (typeof key === 'string') {
    // it's already pem
    return key;
  }
  const bs64 = key.toString('base64');
  const header = `-----BEGIN ${algorithm.toUpperCase()} ${type.toUpperCase()} KEY-----\n`;
  const footer = `\n-----END ${algorithm.toUpperCase()} ${type.toUpperCase()} KEY-----`;
  return `${header}${bs64}${footer}`;
}
