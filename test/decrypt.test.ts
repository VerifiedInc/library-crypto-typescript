import crypto from 'crypto';
import { CredentialPb, CredentialStatus, EncryptedData, Proof, RSAPadding, UnsignedCredential, Credential, UnsignedCredentialPb, UnsignedString } from '@unumid/types';

import { decryptBytes } from '../src/decrypt';
import { encryptBytesHelper } from '../src/encrypt';
import { signBytes } from '../src/sign';
import { generateRsaKeyPair } from '../src/generateRsaKeyPair';
import { generateEccKeyPair } from '../src/generateEccKeyPair';
import { derToPem, decodeKey } from '../src/helpers';
import { CryptoError } from '../src/types/CryptoError';

/**
 * Create cryptographic proof from byte array of a Protobuf object
 * @param data
 * @param privateKey
 * @param method
 * @param encoding
 */
export const createProof = (signature: string, method: string): Proof => {
  const proof: Proof = {
    created: new Date(),
    signatureValue: signature,
    type: 'secp256r1Signature2020',
    verificationMethod: method,
    proofPurpose: 'assertionMethod'
  };

  return (proof);
};

describe('decrypt', () => {
  let publicKey: string;
  let privateKey: string;
  const data: UnsignedString = {
    data: 'Hello World'
  };
  const dataBytes = UnsignedString.encode(data).finish();
  const subjectDid = 'did:unum:c92aed65-21c1-438f-b723-d2ee4a637a47#e939fbf0-7c81-49c9-b369-8ca502fcd19f';
  let encryptedData: EncryptedData;
  let encryptedCredential;
  let credential: Credential;

  beforeEach(() => {
    jest.spyOn(crypto, 'privateDecrypt');
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('using default (pem) encoding', () => {
    beforeAll(async () => {
      const keypair = await generateRsaKeyPair();
      privateKey = keypair.privateKey;
      publicKey = keypair.publicKey;
      encryptedData = encryptBytesHelper(subjectDid, publicKey, dataBytes);

      const eccKeyPair = await generateEccKeyPair();

      const credentialSubject = {
        id: 'did:unum:89460433-c0b7-4892-aeb2-f2ece77af141',
        value: 'dummy value'
      };

      const credentialStatus: CredentialStatus = {
        id: 'https://example.edu/status/24',
        type: 'CredentialStatusList2017'
      };

      const unsignedCredential: UnsignedCredential = {
        context: ['https://www.w3.org/2018/credentials/v1'],
        id: '0c93beb0-2605-4650-b698-3fd92eb110b9',
        credentialSubject: JSON.stringify(credentialSubject),
        credentialStatus,
        issuer: 'did:unum:e1281297-268b-4700-8f17-7fa826effe35',
        type: ['VerifiableCredential', 'DummyCredential'],
        issuanceDate: new Date('2020-05-26T23:07:12.770Z')
      };
      const issuerDid = 'did:unum:756450ab-ab01-420c-838e-cfa0bebdc2ba';

      const unsignedCredentialBytes = UnsignedCredentialPb.encode(unsignedCredential).finish();
      const signatureValue = signBytes(unsignedCredentialBytes, eccKeyPair.privateKey);

      const proof = createProof(signatureValue, `${issuerDid}#5b134be0-7cb4-4983-95b1-bdec218cb55b`);

      credential = {
        ...unsignedCredential,
        proof
      };

      const credentialBytes = CredentialPb.encode(credential).finish();

      encryptedCredential = encryptBytesHelper(
        credential.proof.verificationMethod,
        publicKey,
        credentialBytes
      );
    });

    beforeEach(() => {
      jest.spyOn(crypto, 'privateDecrypt');
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('decrypts with the private key', () => {
      decryptBytes(privateKey, encryptedData);

      const privateKeyObj = {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
      };

      expect(crypto.privateDecrypt).toBeCalled();
      expect((crypto.privateDecrypt as jest.Mock).mock.calls[0][0]).toEqual(privateKeyObj);
    });

    it('returns the decrypted data', () => {
      const decryptedDataBytes = decryptBytes(privateKey, encryptedData);
      const decryptedData = UnsignedString.decode(decryptedDataBytes);
      expect(decryptedData).toEqual(data);
    });

    it('decrypts an actual encrypted credential', () => {
      const decryptedDataBytes = decryptBytes(privateKey, encryptedCredential);
      const decryptedData = CredentialPb.decode(decryptedDataBytes);
      expect(decryptedData).toEqual(credential);
    });
  });

  describe('using base58 encoding', () => {
    const encoding = 'base58';
    beforeAll(async () => {
      const keypair = await generateRsaKeyPair();
      privateKey = keypair.privateKey;
      publicKey = keypair.publicKey;
      encryptedData = encryptBytesHelper(subjectDid, publicKey, dataBytes);

      const eccKeyPair = await generateEccKeyPair();

      const credentialSubject = {
        id: 'did:unum:89460433-c0b7-4892-aeb2-f2ece77af141',
        value: 'dummy value'
      };

      const credentialStatus: CredentialStatus = {
        id: 'https://example.edu/status/24',
        type: 'CredentialStatusList2017'
      };

      const unsignedCredential: UnsignedCredential = {
        context: ['https://www.w3.org/2018/credentials/v1'],
        id: '0c93beb0-2605-4650-b698-3fd92eb110b9',
        credentialSubject: JSON.stringify(credentialSubject),
        credentialStatus,
        issuer: 'did:unum:e1281297-268b-4700-8f17-7fa826effe35',
        type: ['VerifiableCredential', 'DummyCredential'],
        issuanceDate: new Date('2020-05-26T23:07:12.770Z')
      };
      const issuerDid = 'did:unum:756450ab-ab01-420c-838e-cfa0bebdc2ba';

      const unsignedCredentialBytes = UnsignedCredentialPb.encode(unsignedCredential).finish();
      const signatureValue = signBytes(unsignedCredentialBytes, eccKeyPair.privateKey);

      const proof = createProof(signatureValue, `${issuerDid}#5b134be0-7cb4-4983-95b1-bdec218cb55b`);

      credential = {
        ...unsignedCredential,
        proof
      };

      const credentialBytes = CredentialPb.encode(credential).finish();

      encryptedCredential = encryptBytesHelper(
        credential.proof.verificationMethod,
        publicKey,
        credentialBytes
      );
    });

    beforeEach(() => {
      jest.spyOn(crypto, 'privateDecrypt');
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('decrypts with the private key', () => {
      decryptBytes(privateKey, encryptedData);

      const privateKeyObj = {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
      };

      expect(crypto.privateDecrypt).toBeCalled();
      expect((crypto.privateDecrypt as jest.Mock).mock.calls[0][0]).toEqual(privateKeyObj);
    });

    it('returns the decrypted data', () => {
      const decryptedDataBytes = decryptBytes(privateKey, encryptedData);
      const decryptedData = UnsignedString.decode(decryptedDataBytes);
      expect(decryptedData).toEqual(data);
    });

    it('decrypts an actual encrypted credential', () => {
      const decryptedDataBytes = decryptBytes(privateKey, encryptedCredential);
      const decryptedData = CredentialPb.decode(decryptedDataBytes);
      expect(decryptedData).toEqual(credential);
    });
  });

  describe('exception handling', () => {
    const encoding = 'base58';
    beforeAll(async () => {
      const keypair = await generateRsaKeyPair(encoding);
      privateKey = keypair.privateKey;
      publicKey = keypair.publicKey;
      encryptedData = encrypt(subjectDid, publicKey, data, encoding);

      const eccKeyPair = await generateEccKeyPair();

      const unsignedCredential = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        id: '0c93beb0-2605-4650-b698-3fd92eb110b9',
        credentialSubject: {
          id: 'did:unum:89460433-c0b7-4892-aeb2-f2ece77af141',
          value: 'dummy value'
        },
        credentialStatus: {
          uuid: 'c3974fa3-396e-42ee-81a9-9ab69efce031',
          status: 'valid',
          createdAt: '2020-05-26T23:07:12.770Z',
          updatedAt: '2020-05-26T23:07:12.770Z'
        },
        issuer: 'did:unum:e1281297-268b-4700-8f17-7fa826effe35',
        type: ['VerifiableCredential', 'DummyCredential'],
        issuanceDate: '2020-05-26T23:07:12.770Z'
      };
      const issuerDid = 'did:unum:756450ab-ab01-420c-838e-cfa0bebdc2ba';

      const signatureValue = sign(unsignedCredential, eccKeyPair.privateKey);
      credential = {
        ...unsignedCredential,
        proof: {
          created: '2020-05-26T23:07:12.770Z',
          signatureValue,
          proofPurpose: 'assertionMethod',
          type: 'secp256r1Signature2020',
          verificationMethod: `${issuerDid}#5b134be0-7cb4-4983-95b1-bdec218cb55b`
        }
      };

      encryptedCredential = encrypt(
        credential.proof.verificationMethod,
        publicKey,
        credential,
        encoding
      );
    });

    beforeEach(() => {
      jest.spyOn(crypto, 'privateDecrypt');
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('throws CryptoError exception if the input is invalid', async () => {
      try {
        decrypt(privateKey, encryptedData, 'pem');
        fail();
      } catch (e) {
        expect(e).toBeInstanceOf(CryptoError);
      }
    });
  });

  test('rsa padding', async () => {
    const keys = await generateRsaKeyPair();
    const data = Buffer.from('test');
    const mockPrivateDecrypt = crypto.privateDecrypt as jest.Mock;

    const publicKeyInfo = {
      publicKey: keys.publicKey,
      encoding: 'pem'
    };

    // default (PKCS)
    const encryptedDefault = encryptBytesHelper(subjectDid, keys.publicKey, data, 'pem');
    // const encryptedDefault = encryptBytes(subjectDid, publicKeyInfo as PublicKeyInfo, data);

    const decryptedDefault = decryptBytes(
      keys.privateKey,
      { data: encryptedDefault.data, key: encryptedDefault.key }
      // 'pem'
    );

    expect(decryptedDefault).toEqual(data);
    expect((crypto.privateDecrypt as jest.Mock).mock.calls[0][0].padding).toEqual(crypto.constants.RSA_PKCS1_PADDING);

    mockPrivateDecrypt.mockClear();

    // PKCS
    const encryptedPKCS = encryptBytesHelper(subjectDid, keys.publicKey, data, 'pem');
    // const encryptedPKCS = encryptBytes(subjectDid, publicKeyInfo as PublicKeyInfo, data);

    const decryptedPKCS = decryptBytes(keys.privateKey, encryptedPKCS);

    expect(decryptedPKCS).toEqual(data);
    expect((crypto.privateDecrypt as jest.Mock).mock.calls[0][0].padding).toEqual(crypto.constants.RSA_PKCS1_PADDING);

    mockPrivateDecrypt.mockClear();

    // OAEP
    const encryptedOAEP = encryptBytesHelper(subjectDid, keys.publicKey, data, 'pem', RSAPadding.OAEP);

    const decryptedOAEP = decryptBytes(keys.privateKey, encryptedOAEP);

    expect(decryptedOAEP).toEqual(data);
    expect((crypto.privateDecrypt as jest.Mock).mock.calls[0][0].padding).toEqual(crypto.constants.RSA_PKCS1_OAEP_PADDING);
  });
});
