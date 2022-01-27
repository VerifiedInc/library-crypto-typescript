import { KeyPair } from '@unumid/types';
import { detectEncodingType } from '../src';
import { generateEccBase58KeyPair, generateEccPemKeyPair } from '../src/generateEccKeyPair';
import { generateRsaBase58KeyPair, generateRsaPemKeyPair } from '../src/generateRsaKeyPair';

describe('detectKeyEncodingType', () => {
  describe('RSA PEM keys', () => {
    let pemKeys: KeyPair;

    beforeEach(async () => {
      pemKeys = await generateRsaPemKeyPair();
    });

    it('pem public key', () => {
      const type = detectEncodingType(pemKeys.publicKey);

      expect(type).toBe('pem');
    });

    it('pem private key', () => {
      const type = detectEncodingType(pemKeys.privateKey);

      expect(type).toBe('pem');
    });
  });
  describe('RSA Base58 keys', () => {
    let base58Keys: KeyPair;

    beforeEach(async () => {
      base58Keys = await generateRsaBase58KeyPair();
    });
    it('base58 public key', () => {
      const type = detectEncodingType(base58Keys.publicKey);

      expect(type).toBe('base58');
    });

    it('base58 private key', () => {
      const type = detectEncodingType(base58Keys.privateKey);

      expect(type).toBe('base58');
    });
  });

  describe('ECC PEM keys', () => {
    let keys: KeyPair;

    beforeEach(async () => {
      keys = await generateEccPemKeyPair();
    });
    it('pem public key', () => {
      const type = detectEncodingType(keys.publicKey);

      expect(type).toBe('pem');
    });

    it('pem private key', () => {
      const type = detectEncodingType(keys.privateKey);

      expect(type).toBe('pem');
    });
  });

  describe('ECC Base58 keys', () => {
    let keys: KeyPair;

    beforeEach(async () => {
      keys = await generateEccBase58KeyPair();
    });
    it('base58 public key', () => {
      const type = detectEncodingType(keys.publicKey);

      expect(type).toBe('base58');
    });

    it('base58 private key', () => {
      const type = detectEncodingType(keys.privateKey);

      expect(type).toBe('base58');
    });
  });
});
