import { Proof, RSAPadding, UnsignedString } from '@unumid/types';
import crypto from 'crypto';
import stringify from 'fast-json-stable-stringify';

import { encryptBytesHelper, encryptBytes } from '../src/encrypt';
import { generateRsaKeyPair } from '../src/generateRsaKeyPair';
import { derToPem, decodeKey } from '../src/helpers';
import { CryptoError } from '../src/types/CryptoError';

describe('encrypt', () => {
  let publicKey: string;
  const data: UnsignedString = {
    data: 'Hello World'
  };
  const dataBytes = UnsignedString.encode(data).finish();
  const subjectDid = 'did:unum:c92aed65-21c1-438f-b723-d2ee4a637a47#e939fbf0-7c81-49c9-b369-8ca502fcd19f';

  describe('using default (pem) encoding', () => {
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
      encryptBytesHelper(subjectDid, publicKey, dataBytes);
      expect(crypto.createCipheriv).toBeCalled();
      expect((crypto.createCipheriv as jest.Mock).mock.calls[0][0]).toEqual('aes-256-cbc');
    });

    it('encrypts data with the aes cipher', () => {
      const mockUpdate = jest.fn(() => Buffer.from(stringify(data)));
      const mockFinal = jest.fn(() => Buffer.from(stringify(data)));
      (crypto.createCipheriv as jest.Mock).mockReturnValueOnce({ update: mockUpdate, final: mockFinal });
      encryptBytesHelper(subjectDid, publicKey, dataBytes);
      expect(mockUpdate).toBeCalledWith(dataBytes);
      expect(mockFinal).toBeCalled();
    });

    it('encrypts the aes key, iv, and algorithm with the public key', () => {
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(16);
      jest.spyOn(crypto, 'randomBytes')
        .mockImplementationOnce(() => key)
        .mockImplementationOnce(() => iv);

      const publicKeyObj = {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
      };

      encryptBytesHelper(subjectDid, publicKey, dataBytes);
      expect(crypto.publicEncrypt).toBeCalledWith(publicKeyObj, iv);
      expect(crypto.publicEncrypt).toBeCalledWith(publicKeyObj, key);
      expect(crypto.publicEncrypt).toBeCalledWith(publicKeyObj, Buffer.from('aes-256-cbc'));
    });

    it('returns the encrypted data', () => {
      const encryptedData = encryptBytesHelper(subjectDid, publicKey, dataBytes);
      expect(encryptedData.data).toBeDefined();
    });

    it('returns the encrypted key information', () => {
      const encryptedData = encryptBytesHelper(subjectDid, publicKey, dataBytes);
      expect(encryptedData.key).toBeDefined();
      expect(encryptedData.key.iv).toBeDefined();
      expect(encryptedData.key.key).toBeDefined();
      expect(encryptedData.key.algorithm).toBeDefined();
      expect(encryptedData.key.did).toEqual(subjectDid);
    });

    it('includes the rsa padding in the encrypted data, defaulting to PKCS', () => {
      // defaults to pkcs
      const encryptedDataDefault = encryptBytesHelper(subjectDid, publicKey, dataBytes);
      expect(encryptedDataDefault.rsaPadding).toEqual(RSAPadding.PKCS);

      // sets pkcs
      const encryptedDataPKCS = encryptBytesHelper(subjectDid, publicKey, dataBytes, 'pem', RSAPadding.PKCS);
      expect(encryptedDataPKCS.rsaPadding).toEqual(RSAPadding.PKCS);

      // sets oaep
      const encryptedDataOAEP = encryptBytesHelper(subjectDid, publicKey, dataBytes, 'pem', RSAPadding.OAEP);
      expect(encryptedDataOAEP.rsaPadding).toEqual(RSAPadding.OAEP);

      // fails if padding is unrecognized
      try {
        encryptBytesHelper(subjectDid, publicKey, dataBytes, 'pem', RSAPadding.UNRECOGNIZED);
        fail('Unrecognized RSA padding.');
      } catch (e) {
        expect(e).toEqual(new CryptoError('Unrecognized RSA padding.'));
      }
    });
  });

  describe('using pem encoding', () => {
    const encoding = 'pem';
    beforeAll(async () => {
      const keypair = await generateRsaKeyPair(encoding);
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
      encryptBytesHelper(subjectDid, publicKey, dataBytes, encoding);
      expect(crypto.createCipheriv).toBeCalled();
      expect((crypto.createCipheriv as jest.Mock).mock.calls[0][0]).toEqual('aes-256-cbc');
    });

    it('encrypts data with the aes cipher', () => {
      const mockUpdate = jest.fn(() => Buffer.from(stringify(data)));
      const mockFinal = jest.fn(() => Buffer.from(stringify(data)));
      (crypto.createCipheriv as jest.Mock).mockReturnValueOnce({ update: mockUpdate, final: mockFinal });
      encryptBytesHelper(subjectDid, publicKey, dataBytes, encoding);
      expect(mockUpdate).toBeCalledWith(dataBytes);
      expect(mockFinal).toBeCalled();
    });

    it('encrypts the aes key, iv, and algorithm with the public key', () => {
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(16);
      jest.spyOn(crypto, 'randomBytes')
        .mockImplementationOnce(() => key)
        .mockImplementationOnce(() => iv);

      const publicKeyObj = {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
      };

      encryptBytesHelper(subjectDid, publicKey, dataBytes, encoding);
      expect(crypto.publicEncrypt).toBeCalledWith(publicKeyObj, iv);
      expect(crypto.publicEncrypt).toBeCalledWith(publicKeyObj, key);
      expect(crypto.publicEncrypt).toBeCalledWith(publicKeyObj, Buffer.from('aes-256-cbc'));
    });

    it('returns the encrypted data', () => {
      const encryptedData = encryptBytesHelper(subjectDid, publicKey, dataBytes, encoding);
      expect(encryptedData.data).toBeDefined();
    });

    it('returns the encrypted key information', () => {
      const encryptedData = encryptBytesHelper(subjectDid, publicKey, dataBytes, encoding);
      expect(encryptedData.key).toBeDefined();
      expect(encryptedData.key.iv).toBeDefined();
      expect(encryptedData.key.key).toBeDefined();
      expect(encryptedData.key.algorithm).toBeDefined();
      expect(encryptedData.key.did).toEqual(subjectDid);
    });
  });

  describe('using base58 encoding', () => {
    const encoding = 'base58';
    beforeAll(async () => {
      const keypair = await generateRsaKeyPair(encoding);
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
      encryptBytesHelper(subjectDid, publicKey, dataBytes, encoding);
      expect(crypto.createCipheriv).toBeCalled();
      expect((crypto.createCipheriv as jest.Mock).mock.calls[0][0]).toEqual('aes-256-cbc');
    });

    it('encrypts data with the aes cipher', () => {
      const mockUpdate = jest.fn(() => Buffer.from(stringify(data)));
      const mockFinal = jest.fn(() => Buffer.from(stringify(data)));
      (crypto.createCipheriv as jest.Mock).mockReturnValueOnce({ update: mockUpdate, final: mockFinal });
      encryptBytesHelper(subjectDid, publicKey, dataBytes, encoding);
      expect(mockUpdate).toBeCalledWith(dataBytes);
      expect(mockFinal).toBeCalled();
    });

    it('encrypts the aes key, iv, and algorithm with the public key', () => {
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(16);
      jest.spyOn(crypto, 'randomBytes')
        .mockImplementationOnce(() => key)
        .mockImplementationOnce(() => iv);

      const publicKeyPem = derToPem(decodeKey(publicKey, 'base58'), 'public');

      const publicKeyObj = {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_PADDING
      };

      encryptBytesHelper(subjectDid, publicKey, dataBytes, encoding);
      expect(crypto.publicEncrypt).toBeCalledWith(publicKeyObj, iv);
      expect(crypto.publicEncrypt).toBeCalledWith(publicKeyObj, key);
      expect(crypto.publicEncrypt).toBeCalledWith(publicKeyObj, Buffer.from('aes-256-cbc'));
    });

    it('returns the encrypted data', () => {
      const encryptedData = encryptBytesHelper(subjectDid, publicKey, dataBytes, encoding);
      expect(encryptedData.data).toBeDefined();
    });

    it('returns the encrypted key information', () => {
      const encryptedData = encryptBytesHelper(subjectDid, publicKey, dataBytes, encoding);
      expect(encryptedData.key).toBeDefined();
      expect(encryptedData.key.iv).toBeDefined();
      expect(encryptedData.key.key).toBeDefined();
      expect(encryptedData.key.algorithm).toBeDefined();
      expect(encryptedData.key.did).toEqual(subjectDid);
    });
  });

  describe('exception handling', () => {
    const encoding = 'base58';
    beforeAll(async () => {
      const keypair = await generateRsaKeyPair(encoding);
      publicKey = keypair.publicKey;
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('throws CryptoError exception if the input is invalid', async () => {
      try {
        encryptBytesHelper(subjectDid, publicKey, dataBytes, 'pem');
        fail();
      } catch (e) {
        expect(e).toBeInstanceOf(CryptoError);
      }
    });
  });
});
