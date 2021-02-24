import { generateEccKeyPair } from './generateEccKeyPair';
import { generateRsaKeyPair } from './generateRsaKeyPair';
import { sign } from './sign';
import { verify } from './verify';
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
  encrypt,
  decrypt,
  validatePublicKey,
  // types
  CryptoError
};
