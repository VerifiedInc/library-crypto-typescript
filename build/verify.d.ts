import { PublicKeyInfo } from '@unumid/types';
/**
 * Used to verify a byte array. The new defacto verify function thanks to the property of Protobuf's ability to encode to bytes and decode back
 * an object in a deterministic fashion.
 *
 * @param {string} signature base58 signature, like one created with sign()
 * @param {Uint8Array} bytes byte array to verify
 * @param {PublicKeyInfo} publicKey PublicKeyInfo corresponding to the private key used to create the signature (pem or base58)
 * @returns {boolean} true if signature was created by signing data with the private key corresponding to publicKey
 */
export declare function verifyBytes(signature: string, bytes: Uint8Array, publicKey: PublicKeyInfo): boolean;
/**
 * Helper used to verify a byte array. The new defacto verify function thanks to the property of Protobuf's ability to encode to bytes and decode back
 * an object in a deterministic fashion.
 *
 * @param {string} signature base58 signature, like one created with sign()
 * @param {Uint8Array} bytes byte array to verify
 * @param {string} publicKey public key corresponding to the private key used to create the signature (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {boolean} true if signature was created by signing data with the private key corresponding to publicKey
 */
export declare function verifyBytesHelper(signature: string, bytes: Uint8Array, publicKey: string, encoding?: 'base58' | 'pem'): boolean;
//# sourceMappingURL=verify.d.ts.map