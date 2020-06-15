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
    expect((crypto.sign as jest.Mock).mock.calls[0][2]).toEqual(privateKey);
  });

  it('returns the signature', () => {
    const signature = sign(data, privateKey);
    expect(signature).toBeDefined();
  });
});
