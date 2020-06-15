import { promisifiedGenerateKeyPair } from './helpers';

export interface KeyPair {
  privateKey: string;
  publicKey: string;
}

export async function generateEccKeyPair (): Promise<KeyPair> {
  const { publicKey, privateKey } = await promisifiedGenerateKeyPair(
    'ec',
    {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'sec1', format: 'pem' }
    }
  );
  return { publicKey, privateKey };
}
