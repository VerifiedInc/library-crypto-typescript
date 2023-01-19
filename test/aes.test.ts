import crypto, { randomBytes } from 'crypto';
import { UnsignedString } from '@unumid/types';
import stringify from 'fast-json-stable-stringify';
import { Aes } from '../src/aes';

describe('aes', () => {
  const stringValue = 'Hello World';
  const data: UnsignedString = {
    data: stringValue
  };
  const dataBytes = UnsignedString.encode(data).finish();
  const ivBytes = randomBytes(16);

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
      aes.encrypt(dataBytes, ivBytes);
      expect(crypto.createCipheriv).toBeCalled();
      expect((crypto.createCipheriv as jest.Mock).mock.calls[0][0]).toEqual('aes-256-cbc');
    });

    it('encrypts data with the aes cipher', () => {
      const mockUpdate = jest.fn(() => Buffer.from(stringify(data)));
      const mockFinal = jest.fn(() => Buffer.from(stringify(data)));
      (crypto.createCipheriv as jest.Mock).mockReturnValueOnce({ update: mockUpdate, final: mockFinal });
      aes.encrypt(dataBytes, ivBytes);
      expect(mockUpdate).toBeCalledWith(dataBytes);
      expect(mockFinal).toBeCalled();
    });

    it('returns the encrypted data', () => {
      const encryptedData = aes.encrypt(dataBytes, ivBytes);
      expect(encryptedData).toBeDefined();
    });
  });

  describe('decrypt', () => {
    beforeAll(async () => {
      encryptedData = aes.encrypt(dataBytes, ivBytes);
    });

    beforeEach(() => {
      jest.spyOn(crypto, 'createDecipheriv');
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('creates an aes cipher to decrypt the data', () => {
      aes.decrypt(encryptedData, ivBytes);
      expect(crypto.createDecipheriv).toBeCalled();
      expect((crypto.createDecipheriv as jest.Mock).mock.calls[0][0]).toEqual('aes-256-cbc');
    });

    it('decrypts data with the aes cipher', () => {
      const mockUpdate = jest.fn(() => Buffer.from(stringify(data)));
      const mockFinal = jest.fn(() => Buffer.from(stringify(data)));
      (crypto.createDecipheriv as jest.Mock).mockReturnValueOnce({ update: mockUpdate, final: mockFinal });
      aes.decrypt(encryptedData, ivBytes);
      expect(mockUpdate).toBeCalledWith(encryptedData);
      expect(mockFinal).toBeCalled();
    });

    it('returns the decrypted data', () => {
      const decryptedData = aes.decrypt(encryptedData, ivBytes);
      expect(decryptedData).toBeDefined();
      expect(decryptedData).toEqual(dataBytes);

      const decryptedUnsignedString: UnsignedString = UnsignedString.decode(decryptedData);
      expect(decryptedUnsignedString).toEqual(data);
      expect(decryptedUnsignedString.data).toEqual(stringValue);
    });
  });
});
