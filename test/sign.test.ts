import crypto from 'crypto';

import { sign } from '../src/sign';
import { generateEccKeyPair } from '../src/generateEccKeyPair';

describe('sign', () => {
  const data = { test: 'test' };
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
    sign(data, privateKey);
    expect(crypto.sign).toBeCalled();

    const privateKeyObj = crypto.createPrivateKey(privateKey);
    expect((crypto.sign as jest.Mock).mock.calls[0][2]).toEqual(privateKeyObj);
  });

  it('returns the signature', () => {
    const signature = sign(data, privateKey);
    expect(signature).toBeDefined();
  });

  it('works with a base58 encoded key', async () => {
    const base58KeyPair = await generateEccKeyPair('base58');
    const signature = sign(data, base58KeyPair.privateKey, 'base58');
    expect(signature).toBeDefined();
  });
});
