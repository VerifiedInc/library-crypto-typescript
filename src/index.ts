import { generateEccKeyPair } from './generateEccKeyPair';
import { generateRsaKeyPair } from './generateRsaKeyPair';
import { sign, signBytes, signBytesV2 } from './sign';
import { verify, verifyString, verifyBytes, verifyBytesV2 } from './verify';
import { encrypt, encryptBytes, encryptBytesV2 } from './encrypt';
import { decrypt, decryptBytes, decryptBytesV2 } from './decrypt';
import { validatePublicKey } from './validatePublicKey';
import { CryptoError } from './types/CryptoError';

export {
  // functions
  generateEccKeyPair,
  generateRsaKeyPair,
  sign,
  signBytes,
  signBytesV2,
  verify,
  verifyString,
  verifyBytes,
  verifyBytesV2,
  encrypt,
  encryptBytes,
  encryptBytesV2,
  decrypt,
  decryptBytes,
  decryptBytesV2,
  validatePublicKey,
  // types
  CryptoError
};
