import crypto from 'crypto';

import { verifyBytes, verifyBytesHelper } from '../src/verify';
import { generateEccKeyPair } from '../src/generateEccKeyPair';
import { signBytes } from '../src/sign';
import { CryptoError } from '../src/types/CryptoError';
import { UnsignedString } from '@unumid/types';

describe('verify', () => {
  const data: UnsignedString = {
    data: 'Hello World'
  };
  const dataBytes = UnsignedString.encode(data).finish();

  let signature: string;
  let privateKey: string;
  let publicKey: string;

  beforeAll(async () => {
    const keyPair = await generateEccKeyPair();
    privateKey = keyPair.privateKey;
    publicKey = keyPair.publicKey;
    signature = signBytes(dataBytes, privateKey);
  });

  beforeEach(() => {
    jest.spyOn(crypto, 'verify');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('verifies a signature', () => {
    verifyBytesHelper(signature, dataBytes, publicKey, 'pem');
    expect(crypto.verify).toBeCalled();
  });

  it('returns true if the signature is valid', () => {
    const isVerified = verifyBytesHelper(signature, dataBytes, publicKey, 'pem');
    expect(isVerified).toBe(true);
  });

  it('returns false if the signature is not valid', () => {
    const invalidData: UnsignedString = {
      data: 'Hello Mars'
    };
    const invalidDataBytes = UnsignedString.encode(invalidData).finish();

    const isVerified = verifyBytesHelper(signature, invalidDataBytes, publicKey, 'pem');
    expect(isVerified).toBe(false);
  });

  it('works with a base58 encoded key', async () => {
    const base58KeyPair = await generateEccKeyPair('base58');
    signature = signBytes(dataBytes, base58KeyPair.privateKey);
    const isVerified = verifyBytesHelper(signature, dataBytes, base58KeyPair.publicKey, 'base58');
    expect(isVerified).toBe(true);
  });

  it('throws CryptoError exception if public key is missing', async () => {
    try {
      const base58KeyPair = await generateEccKeyPair('base58');
      signature = signBytes(dataBytes, base58KeyPair.privateKey);
      verifyBytes(signature, dataBytes, { publicKey: undefined, encoding: 'pem' });
      fail();
    } catch (e) {
      expect(e).toBeInstanceOf(CryptoError);
    }
  });

  it('throws CryptoError exception if public key encoding is missing', async () => {
    try {
      const base58KeyPair = await generateEccKeyPair('base58');
      signature = signBytes(dataBytes, base58KeyPair.privateKey);
      verifyBytes(signature, dataBytes, { publicKey: base58KeyPair.publicKey, encoding: undefined });
      fail();
    } catch (e) {
      expect(e).toBeInstanceOf(CryptoError);
    }
  });
});
