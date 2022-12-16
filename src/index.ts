import { generateEccKeyPair } from './generateEccKeyPair';
import { generateRsaKeyPair } from './generateRsaKeyPair';
import { signBytes } from './sign';
import { verifyBytes, verifyBytesHelper } from './verify';
import { encryptBytes, encryptBytesHelper } from './encrypt';
import { decryptBytes } from './decrypt';
import { validatePublicKey } from './validatePublicKey';
import { CryptoError } from './types/CryptoError';
import { detectEncodingType } from './utils';
import { Aes } from './aes';

export {
  // functions
  generateEccKeyPair,
  generateRsaKeyPair,
  signBytes,
  verifyBytesHelper,
  verifyBytes,
  encryptBytesHelper,
  encryptBytes,
  decryptBytes,
  validatePublicKey,
  // classes
  Aes,
  // utils
  detectEncodingType,
  // types
  CryptoError
};
