import crypto from 'crypto';

import { decrypt } from '../src/decrypt';
import { encrypt } from '../src/encrypt';
import { generateRsaKeyPair } from '../src/generateRsaKeyPair';
import { EncryptedData } from '../src/types';

describe('decrypt', () => {
  let publicKey: string;
  let privateKey: string;
  const data = { test: 'test' };
  const subjectDid = 'did:unum:c92aed65-21c1-438f-b723-d2ee4a637a47#e939fbf0-7c81-49c9-b369-8ca502fcd19f';
  let encryptedData: EncryptedData;

  beforeAll(async () => {
    const keypair = await generateRsaKeyPair();
    privateKey = keypair.privateKey;
    publicKey = keypair.publicKey;
    encryptedData = encrypt(subjectDid, publicKey, data);
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
