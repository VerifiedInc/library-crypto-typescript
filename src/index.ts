import { generateEccKeyPair } from './generateEccKeyPair';
import { generateRsaKeyPair } from './generateRsaKeyPair';
import { sign, signBytes } from './sign';
import { verify, verifyString, verifyBytes, verifyBytesHelper } from './verify';
import { encrypt, encryptBytes, encryptBytesHelper } from './encrypt';
import { decrypt, decryptBytes } from './decrypt';
import { validatePublicKey } from './validatePublicKey';
import { CryptoError } from './types/CryptoError';
import { detectEncodingType } from './utils';

export {
  // functions
  generateEccKeyPair,
  generateRsaKeyPair,
  sign,
  signBytes,
  verify,
  verifyString,
  verifyBytesHelper,
  verifyBytes,
  encrypt,
  encryptBytesHelper,
  encryptBytes,
  decrypt,
  decryptBytes,
  validatePublicKey,
  // utils
  detectEncodingType,
  // types
  CryptoError
};
