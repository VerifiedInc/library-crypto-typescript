import { promisifiedGenerateKeyPair } from './helpers';
import { KeyPair } from './types';

export async function generateRsaKeyPair (): Promise<KeyPair> {
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
