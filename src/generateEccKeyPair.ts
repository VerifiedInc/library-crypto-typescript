import bs58 from 'bs58';

import { promisifiedGenerateKeyPair } from './helpers';
import { KeyPair } from './types';

export async function generateEccKeyPair (encoding: 'base58' | 'pem' = 'pem'): Promise<KeyPair> {
  switch (encoding) {
    case 'base58':
      return await generateEccBase58KeyPair();
    case 'pem':
      return await generateEccPemKeyPair();
  }
}

export async function generateEccPemKeyPair (): Promise<KeyPair> {
  const { publicKey, privateKey } = await promisifiedGenerateKeyPair(
    'ec',
    {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    }
  );
  return { publicKey, privateKey };
}

export async function generateEccBase58KeyPair (): Promise<KeyPair> {
  const { publicKey, privateKey } = await promisifiedGenerateKeyPair(
    'ec',
    {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    }
  );

  return {
    publicKey: bs58.encode(publicKey),
    privateKey: bs58.encode(privateKey)
  };
}
