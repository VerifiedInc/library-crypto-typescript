import { generateEccKeyPair } from './generateEccKeyPair';
import { generateRsaKeyPair } from './generateRsaKeyPair';
import { sign } from './sign';
import { verify, verifyString } from './verify';
import { encrypt } from './encrypt';
import { decrypt } from './decrypt';
import { validatePublicKey } from './validatePublicKey';
import { CryptoError } from './types/CryptoError';

export {
  // functions
  generateEccKeyPair,
  generateRsaKeyPair,
  sign,
  verify,
  verifyString,
  encrypt,
  decrypt,
  validatePublicKey,
  // types
  CryptoError
};
