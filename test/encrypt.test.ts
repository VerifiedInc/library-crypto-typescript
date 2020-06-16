import crypto from 'crypto';

import { encrypt } from '../src/encrypt';
import { generateRsaKeyPair } from '../src/generateRsaKeyPair';

describe('encrypt', () => {
  let publicKey: string;
  const data = { test: 'test' };
  beforeAll(async () => {
    const keypair = await generateRsaKeyPair();
    publicKey = keypair.publicKey;
  });

  beforeEach(() => {
    jest.spyOn(crypto, 'publicEncrypt');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('encrypts data with the public key', () => {
    encrypt(publicKey, data);
    expect(crypto.publicEncrypt).toBeCalled();
    expect((crypto.publicEncrypt as jest.Mock).mock.calls[0][0]).toEqual(publicKey);
  });

  it('returns the encrypted data', () => {
    const encryptedData = encrypt(publicKey, data);
    expect(encryptedData).toBeDefined();
  });
});
