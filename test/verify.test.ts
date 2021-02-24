import crypto from 'crypto';

import { verify } from '../src/verify';
import { generateEccKeyPair } from '../src/generateEccKeyPair';
import { sign } from '../src/sign';
import { CryptoError } from '../src/types/CryptoError';

describe('verify', () => {
  const data = { test: 'test' };
  let signature: string;
  let privateKey: string;
  let publicKey: string;

  beforeAll(async () => {
    const keyPair = await generateEccKeyPair();
    privateKey = keyPair.privateKey;
    publicKey = keyPair.publicKey;
    signature = sign(data, privateKey);
  });

  beforeEach(() => {
    jest.spyOn(crypto, 'verify');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('verifies a signature', () => {
    verify(signature, data, publicKey);
    expect(crypto.verify).toBeCalled();
  });

  it('returns true if the signature is valid', () => {
    const isVerified = verify(signature, data, publicKey);
    expect(isVerified).toBe(true);
  });

  it('returns false if the signature is not valid', () => {
    const invalidData = { ...data, updated: true };
    const isVerified = verify(signature, invalidData, publicKey);
    expect(isVerified).toBe(false);
  });

  it('works with a base58 encoded key', async () => {
    const base58KeyPair = await generateEccKeyPair('base58');
    signature = sign(data, base58KeyPair.privateKey, 'base58');
    const isVerified = verify(signature, data, base58KeyPair.publicKey, 'base58');
    expect(isVerified).toBe(true);
  });

  it('throws CryptoError exception if invalid input', async () => {
    try {
      const base58KeyPair = await generateEccKeyPair('base58');
      signature = sign(data, base58KeyPair.privateKey, 'base58');
      verify(signature, data, base58KeyPair.publicKey, 'pem');
      fail();
    } catch (e) {
      expect(e).toBeInstanceOf(CryptoError);
    }
  });
});
