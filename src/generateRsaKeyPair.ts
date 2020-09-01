import bs58 from 'bs58';

import { promisifiedGenerateKeyPair } from './helpers';
import { KeyPair } from './types';

export async function generateRsaKeyPair (encoding: 'base58' | 'pem' = 'pem'): Promise<KeyPair> {
  switch (encoding) {
    case 'base58':
      return await generateRsaBase58KeyPair();
    case 'pem':
      return await generateRsaPemKeyPair();
  }
}

export async function generateRsaPemKeyPair (): Promise<KeyPair> {
  const { publicKey, privateKey } = await promisifiedGenerateKeyPair(
    'rsa',
    {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
    }
  );
  return { publicKey, privateKey };
}

export async function generateRsaBase58KeyPair (): Promise<KeyPair> {
  const { publicKey, privateKey } = await promisifiedGenerateKeyPair(
    'rsa',
    {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'pkcs1', format: 'der' },
      privateKeyEncoding: { type: 'pkcs1', format: 'der' }
    }
  );
  return {
    publicKey: bs58.encode(publicKey),
    privateKey: bs58.encode(privateKey)
  };
}
