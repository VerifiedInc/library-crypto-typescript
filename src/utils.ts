import { RSAPadding } from '@unumid/types';
import { constants } from 'crypto';
import { CryptoError } from '.';

export function getPadding (padding: RSAPadding): number {
  switch (padding) {
    case RSAPadding.PKCS: return constants.RSA_PKCS1_PADDING;
    case RSAPadding.OAEP: return constants.RSA_PKCS1_OAEP_PADDING;
    default: {
      throw new CryptoError('Unrecognized RSA padding.');
    }
  }
}
