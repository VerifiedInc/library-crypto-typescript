import crypto from 'crypto';

import stringify from 'fast-json-stable-stringify';
import { encrypt } from '../src/encrypt';
import { generateRsaKeyPair } from '../src/generateRsaKeyPair';

describe('encrypt', () => {
  let publicKey: string;
  const data = { test: 'test' };
  const subjectDid = 'did:unum:c92aed65-21c1-438f-b723-d2ee4a637a47#e939fbf0-7c81-49c9-b369-8ca502fcd19f';
  beforeAll(async () => {
    const keypair = await generateRsaKeyPair();
    publicKey = keypair.publicKey;
  });

  beforeEach(() => {
    jest.spyOn(crypto, 'publicEncrypt');
    jest.spyOn(crypto, 'createCipheriv');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('creates an aes cipher to encrypt the data', () => {
    encrypt(subjectDid, publicKey, data);
    expect(crypto.createCipheriv).toBeCalled();
    expect((crypto.createCipheriv as jest.Mock).mock.calls[0][0]).toEqual('aes-256-cbc');
  });

  it('encrypts data with the aes cipher', () => {
    const mockUpdate = jest.fn(() => Buffer.from(stringify(data)));
    const mockFinal = jest.fn(() => Buffer.from(stringify(data)));
    (crypto.createCipheriv as jest.Mock).mockReturnValueOnce({ update: mockUpdate, final: mockFinal });
    encrypt(subjectDid, publicKey, data);
    expect(mockUpdate).toBeCalledWith(stringify(data));
    expect(mockFinal).toBeCalled();
  });

  it('encrypts the aes key, iv, and algorithm with the public key', () => {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    jest.spyOn(crypto, 'randomBytes')
      .mockImplementationOnce(() => key)
      .mockImplementationOnce(() => iv);

    encrypt(subjectDid, publicKey, data);
    expect(crypto.publicEncrypt).toBeCalledWith(publicKey, iv);
    expect(crypto.publicEncrypt).toBeCalledWith(publicKey, key);
    expect(crypto.publicEncrypt).toBeCalledWith(publicKey, Buffer.from('aes-256-cbc'));
  });

  it('returns the encrypted data', () => {
    const encryptedData = encrypt(subjectDid, publicKey, data);
    expect(encryptedData.data).toBeDefined();
  });

  it('returns the encrypted key information', () => {
    const encryptedData = encrypt(subjectDid, publicKey, data);
    expect(encryptedData.key).toBeDefined();
    expect(encryptedData.key.iv).toBeDefined();
    expect(encryptedData.key.key).toBeDefined();
    expect(encryptedData.key.algorithm).toBeDefined();
    expect(encryptedData.key.did).toEqual(subjectDid);
  });
});
