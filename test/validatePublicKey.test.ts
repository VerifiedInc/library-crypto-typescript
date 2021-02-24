import crypto from 'crypto';

import { validatePublicKey } from '../src/validatePublicKey';
import { generateEccKeyPair } from '../src/generateEccKeyPair';

describe('validatePublicKey', () => {
  let privateKey: string;
  let publicKey: string;

  beforeAll(async () => {
    const keyPair = await generateEccKeyPair();
    privateKey = keyPair.privateKey;
    publicKey = keyPair.publicKey;
  });

  beforeEach(() => {
    jest.spyOn(crypto, 'createPublicKey');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('verifies calls crypto.createPublicKey', () => {
    validatePublicKey(publicKey);
    expect(crypto.createPublicKey).toBeCalled();
  });

  it('returns true if valid', () => {
    const isValid = validatePublicKey(publicKey);
    expect(isValid).toBe(true);
  });

  it('throws exception if the key is not valid', async () => {
    try {
      const base58KeyPair = await generateEccKeyPair('base58');
      validatePublicKey(base58KeyPair.publicKey, 'pem');
      fail();
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  it('works with a base58 encoded key', async () => {
    const base58KeyPair = await generateEccKeyPair('base58');
    const isValid = validatePublicKey(base58KeyPair.publicKey, 'base58');
    expect(isValid).toBe(true);
  });
});
