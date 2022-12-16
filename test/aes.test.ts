import crypto from 'crypto';
import { Proof, RSAPadding, UnsignedString } from '@unumid/types';
import { PublicKeyInfo } from '@unumid/types/build/protos/crypto';
import stringify from 'fast-json-stable-stringify';
import { Aes } from '../src/aes';

import { encryptBytesHelper, encryptBytes } from '../src/encrypt';
import { generateRsaKeyPair } from '../src/generateRsaKeyPair';
import { derToPem, decodeKey } from '../src/helpers';
import { CryptoError } from '../src/types/CryptoError';

describe('aes', () => {
  const data: UnsignedString = {
    data: 'Hello World'
  };
  const dataBytes = UnsignedString.encode(data).finish();

  const aes = new Aes();
  let encryptedData: Buffer;

  describe('encrypt', () => {
    beforeAll(async () => {
      // aes = new Aes();
    });

    beforeEach(() => {
      jest.spyOn(crypto, 'createCipheriv');
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('creates an aes cipher to encrypt the data', () => {
      aes.encrypt(dataBytes);
      expect(crypto.createCipheriv).toBeCalled();
      expect((crypto.createCipheriv as jest.Mock).mock.calls[0][0]).toEqual('aes-256-cbc');
    });

    it('encrypts data with the aes cipher', () => {
      const mockUpdate = jest.fn(() => Buffer.from(stringify(data)));
      const mockFinal = jest.fn(() => Buffer.from(stringify(data)));
      (crypto.createCipheriv as jest.Mock).mockReturnValueOnce({ update: mockUpdate, final: mockFinal });
      aes.encrypt(dataBytes);
      expect(mockUpdate).toBeCalledWith(dataBytes);
      expect(mockFinal).toBeCalled();
    });

    it('returns the encrypted data', () => {
      const encryptedData = aes.encrypt(dataBytes);
      expect(encryptedData).toBeDefined();
    });
  });

  describe('decrypt', () => {
    beforeAll(async () => {
      encryptedData = aes.encrypt(dataBytes);
    });

    beforeEach(() => {
      jest.spyOn(crypto, 'createDecipheriv');
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('creates an aes cipher to decrypt the data', () => {
      aes.decrypt(encryptedData);
      expect(crypto.createDecipheriv).toBeCalled();
      expect((crypto.createDecipheriv as jest.Mock).mock.calls[0][0]).toEqual('aes-256-cbc');
    });

    it('decrypts data with the aes cipher', () => {
      const mockUpdate = jest.fn(() => Buffer.from(stringify(data)));
      const mockFinal = jest.fn(() => Buffer.from(stringify(data)));
      (crypto.createDecipheriv as jest.Mock).mockReturnValueOnce({ update: mockUpdate, final: mockFinal });
      aes.decrypt(encryptedData);
      expect(mockUpdate).toBeCalledWith(encryptedData);
      expect(mockFinal).toBeCalled();
    });

    it('returns the decrypted data', () => {
      const decryptedData = aes.decrypt(encryptedData);
      expect(decryptedData).toBeDefined();
      expect(decryptedData).toEqual(dataBytes);

      const decryptedUnsignedString: UnsignedString = UnsignedString.decode(decryptedData);
      expect(decryptedUnsignedString).toEqual(data);
    });
  });

  // describe('exception handling', () => {
  //   const encoding = 'base58';
  //   beforeAll(async () => {
  //     const keypair = await generateRsaKeyPair(encoding);
  //     publicKey = keypair.publicKey;
  //   });

  //   afterEach(() => {
  //     jest.restoreAllMocks();
  //   });

  //   it('throws CryptoError exception if the input is invalid', async () => {
  //     try {
  //       encryptBytesHelper(subjectDid, publicKey, dataBytes, 'pem');
  //       fail();
  //     } catch (e) {
  //       expect(e).toBeInstanceOf(CryptoError);
  //     }
  //   });

  //   it('throws CryptoError exception if the public key is missing', async () => {
  //     const publicKeyInfo: PublicKeyInfo = {
  //       publicKey: undefined,
  //       encoding: 'pem',
  //       rsaPadding: RSAPadding.PKCS
  //     };

  //     try {
  //       encryptBytes(subjectDid, publicKeyInfo, dataBytes);
  //       fail();
  //     } catch (e) {
  //       expect(e).toBeInstanceOf(CryptoError);
  //     }
  //   });

  //   it('throws CryptoError exception if the public key encoding is missing', async () => {
  //     const publicKeyInfo: PublicKeyInfo = {
  //       publicKey,
  //       encoding: undefined,
  //       rsaPadding: RSAPadding.PKCS
  //     };

  //     try {
  //       encryptBytes(subjectDid, publicKeyInfo, dataBytes);
  //       fail();
  //     } catch (e) {
  //       expect(e).toBeInstanceOf(CryptoError);
  //     }
  //   });
  // });
});
