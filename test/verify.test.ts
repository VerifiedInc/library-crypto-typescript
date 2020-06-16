import crypto from 'crypto';

import { verify } from '../src/verify';
import { generateEccKeyPair } from '../src/generateEccKeyPair';
import { sign } from '../src/sign';

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
});
