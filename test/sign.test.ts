import crypto from 'crypto';

import { signBytes } from '../src/sign';
import { generateEccKeyPair } from '../src/generateEccKeyPair';
import { CryptoError } from '../src/types/CryptoError';
import { UnsignedString } from '@unumid/types';

describe('sign', () => {
  const data: UnsignedString = {
    data: 'Hello World'
  };
  const dataBytes = UnsignedString.encode(data).finish();
  let privateKey: string;

  beforeAll(async () => {
    const keyPair = await generateEccKeyPair();
    privateKey = keyPair.privateKey;
  });

  beforeEach(() => {
    jest.spyOn(crypto, 'sign');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('signs the data with the private key', () => {
    signBytes(dataBytes, privateKey);
    expect(crypto.sign).toBeCalled();

    const privateKeyObj = crypto.createPrivateKey(privateKey);
    expect((crypto.sign as jest.Mock).mock.calls[0][2]).toEqual(privateKeyObj);
  });

  it('returns the signature', () => {
    const signature = signBytes(dataBytes, privateKey);
    expect(signature).toBeDefined();
  });

  it('works with a base58 encoded key', async () => {
    const base58KeyPair = await generateEccKeyPair('base58');
    const signature = signBytes(dataBytes, base58KeyPair.privateKey);
    expect(signature).toBeDefined();
  });

  it('throws CryptoError exception if private key is missing', async () => {
    try {
      const signature = signBytes(dataBytes, undefined);
      expect(signature).toBeDefined();
      fail();
    } catch (e) {
      expect(e).toBeInstanceOf(CryptoError);
    }
  });
});
