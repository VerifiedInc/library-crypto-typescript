import crypto from 'crypto';

import { decrypt } from '../src/decrypt';
import { encrypt } from '../src/encrypt';
import { generateRsaKeyPair } from '../src/generateRsaKeyPair';

describe('decrypt', () => {
  let publicKey: string;
  let privateKey: string;
  const data = { test: 'test' };
  let encryptedData: string;

  beforeAll(async () => {
    const keypair = await generateRsaKeyPair();
    privateKey = keypair.privateKey;
    publicKey = keypair.publicKey;
    encryptedData = encrypt(publicKey, data);
  });

  beforeEach(() => {
    jest.spyOn(crypto, 'privateDecrypt');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('decrypts with the private key', () => {
    decrypt(privateKey, encryptedData);
    expect(crypto.privateDecrypt).toBeCalled();
    expect((crypto.privateDecrypt as jest.Mock).mock.calls[0][0]).toEqual(privateKey);
  });

  it('returns the decrypted data', () => {
    const decryptedData = decrypt(privateKey, encryptedData);
    expect(decryptedData).toEqual(data);
  });
});
