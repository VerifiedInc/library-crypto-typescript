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

/**
 * Helper to detect the key encoding type.
 *
 * This check could probably be made more robust, however this works for now.
 * @param key
 * @returns
 */
export function detectEncodingType (key: string): 'base58' | 'pem' {
  if (key.startsWith('-----BEGIN PUBLIC KEY-----')) {
    return 'pem';
  } else if (key.startsWith('-----BEGIN RSA PUBLIC KEY-----')) {
    return 'pem';
  } else if (key.startsWith('-----BEGIN CERTIFICATE-----')) {
    return 'pem';
  } else if (key.startsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----')) {
    return 'pem';
  } else if (key.startsWith('-----BEGIN PRIVATE KEY-----')) {
    return 'pem';
  } else if (key.startsWith('-----BEGIN RSA PRIVATE KEY-----')) {
    return 'pem';
  } else if (key.startsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----')) {
    return 'pem';
  } else if (key.startsWith('-----BEGIN CERTIFICATE REQUEST-----')) {
    return 'pem';
  } else if (key.startsWith('-----BEGIN DSA PRIVATE KEY-----')) {
    return 'pem';
  } else if (key.startsWith('-----BEGIN EC PRIVATE KEY-----')) {
    return 'pem';
  } else if (key.startsWith('-----BEGIN DSA PRIVATE KEY-----')) {
    return 'pem';
  } else if (key.startsWith('-----BEGIN EC PRIVATE KEY-----')) {
    return 'pem';
  } else if (key.startsWith('-----BEGIN PRIVATE KEY-----')) {
    return 'pem';
  } else if (key.startsWith('-----BEGIN RSA PRIVATE KEY-----')) {
    return 'pem';
  } else if (key.startsWith('-----BEGIN DSA PRIVATE KEY-----')) {
    return 'pem';
  } else if (key.startsWith('-----BEGIN EC PRIVATE KEY-----')) {
    return 'pem';
  }

  return 'base58';
}
