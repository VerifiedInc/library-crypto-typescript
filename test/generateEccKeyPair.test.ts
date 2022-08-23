import bs58 from 'bs58';

import * as helpers from '../src/helpers';

import { generateEccKeyPair } from '../src/generateEccKeyPair';
import { KeyPair } from '@unumid/types';

describe('generateEccKeypair', () => {
  let result: KeyPair;

  describe('default', () => {
    beforeEach(async () => {
      jest.spyOn(helpers, 'promisifiedGenerateKeyPair');
      result = await generateEccKeyPair();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it('generates a secp256r1 keypair', () => {
      expect(helpers.promisifiedGenerateKeyPair).toBeCalled();
      expect((helpers.promisifiedGenerateKeyPair as jest.Mock).mock.calls[0][0]).toEqual('ec');
      expect((helpers.promisifiedGenerateKeyPair as jest.Mock).mock.calls[0][1].namedCurve).toEqual('prime256v1');
    });

    it('returns a pem-encoded keypair by default', () => {
      expect(result.privateKey).toBeDefined();
      expect(result.publicKey).toBeDefined();
      expect(result.privateKey.startsWith('-----BEGIN PRIVATE KEY-----')).toBe(true);
      expect(result.publicKey.startsWith('-----BEGIN PUBLIC KEY-----')).toBe(true);
    });
  });

  describe('pem encoding', () => {
    beforeEach(async () => {
      jest.spyOn(helpers, 'promisifiedGenerateKeyPair');
      result = await generateEccKeyPair('pem');
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it('generates a secp256r1 keypair', () => {
      expect(helpers.promisifiedGenerateKeyPair).toBeCalled();
      expect((helpers.promisifiedGenerateKeyPair as jest.Mock).mock.calls[0][0]).toEqual('ec');
      expect((helpers.promisifiedGenerateKeyPair as jest.Mock).mock.calls[0][1].namedCurve).toEqual('prime256v1');
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
      result = await generateEccKeyPair('base58');
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    it('generates a secp256r1 keypair', () => {
      expect(helpers.promisifiedGenerateKeyPair).toBeCalled();
      expect((helpers.promisifiedGenerateKeyPair as jest.Mock).mock.calls[0][0]).toEqual('ec');
      expect((helpers.promisifiedGenerateKeyPair as jest.Mock).mock.calls[0][1].namedCurve).toEqual('prime256v1');
    });

    it('returns a base58-encoded keypair', () => {
      expect(result.id).toBeDefined();
      expect(result.privateKey).toBeDefined();
      expect(result.publicKey).toBeDefined();
      expect(() => bs58.decode(result.privateKey)).not.toThrow();
      expect(() => bs58.decode(result.publicKey)).not.toThrow();
    });
  });
});
