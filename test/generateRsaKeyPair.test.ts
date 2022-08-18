import bs58 from 'bs58';
import { KeyPair } from '@unumid/types';

import * as helpers from '../src/helpers';

import { generateRsaKeyPair } from '../src/generateRsaKeyPair';

describe('generateRsaKeypair', () => {
  let result: KeyPair;

  describe('default', () => {
    beforeEach(async () => {
      jest.spyOn(helpers, 'promisifiedGenerateKeyPair');
      result = await generateRsaKeyPair();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it('generates an RSA keypair', () => {
      expect(helpers.promisifiedGenerateKeyPair).toBeCalled();
      expect((helpers.promisifiedGenerateKeyPair as jest.Mock).mock.calls[0][0]).toEqual('rsa');
    });

    it('returns a pem-encoded keypair by default', () => {
      expect(result.id).toBeDefined();
      expect(result.privateKey).toBeDefined();
      expect(result.publicKey).toBeDefined();
      expect(result.privateKey.startsWith('-----BEGIN PRIVATE KEY-----')).toBe(true);
      expect(result.publicKey.startsWith('-----BEGIN PUBLIC KEY-----')).toBe(true);
    });
  });

  describe('pem encoding', () => {
    beforeEach(async () => {
      jest.spyOn(helpers, 'promisifiedGenerateKeyPair');
      result = await generateRsaKeyPair('pem');
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it('generates an RSA keypair', () => {
      expect(helpers.promisifiedGenerateKeyPair).toBeCalled();
      expect((helpers.promisifiedGenerateKeyPair as jest.Mock).mock.calls[0][0]).toEqual('rsa');
    });

    it('returns a pem-encoded keypair', () => {
      expect(result.id).toBeDefined();
      expect(result.privateKey).toBeDefined();
      expect(result.publicKey).toBeDefined();
      expect(result.privateKey.startsWith('-----BEGIN PRIVATE KEY-----')).toBe(true);
      expect(result.publicKey.startsWith('-----BEGIN PUBLIC KEY-----')).toBe(true);
    });
  });

  describe('base58', () => {
    beforeEach(async () => {
      jest.spyOn(helpers, 'promisifiedGenerateKeyPair');
      result = await generateRsaKeyPair('base58');
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it('generates an RSA keypair', () => {
      expect(helpers.promisifiedGenerateKeyPair).toBeCalled();
      expect((helpers.promisifiedGenerateKeyPair as jest.Mock).mock.calls[0][0]).toEqual('rsa');
    });

    it('returns a base58-encoded keypair', () => {
      expect(result.id).toBeDefined();
      expect(result.privateKey).toBeDefined();
      expect(result.publicKey).toBeDefined();
      expect(() => Buffer.from(result.privateKey, 'base64')).not.toThrow();
      expect(() => Buffer.from(result.publicKey, 'base64')).not.toThrow();
    });
  });
});
