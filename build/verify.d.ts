/**
 * Used to verify the provide data object against a provided Base58 encode signature.
 * Should only be used if dealing with projects can ensure identical data object string encoding.
 * For this reason it deprecated in favor of using Protobufs for objects that need to be signed and leveraging signBytes.
 *
 * @param {string} signature base58 signature, like one created with sign()
 * @param {any} data data to verify (JSON-serializable object)
 * @param {string} publicKey public key corresponding to the private key used to create the signature (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {boolean} true if signature was created by signing data with the private key corresponding to publicKey
 */
export declare function verify(signature: string, data: unknown, publicKey: string, encoding?: 'base58' | 'pem'): boolean;
/**
 * Used to verify the provide data string against a provided Base58 encode signature.
 * A less than ideal situation of being handling a string representation of the signed object for reason of then having to convert back to the object.
 * For this reason it deprecated in favor of using Protobufs for objects that need to be signed and verified.
 *
 * @param {string} signature base58 signature, like one created with sign()
 * @param {string} stringifiedData data (JSON-serializable object) as a string to verify
 * @param {string} publicKey public key corresponding to the private key used to create the signature (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {boolean} true if signature was created by signing data with the private key corresponding to publicKey
 */
export declare function verifyString(signature: string, stringifiedData: string, publicKey: string, encoding?: 'base58' | 'pem'): boolean;
/**
 * Used to verify a byte array. Exported thanks to the property of Protobuf's ability to encode to bytes and decode back
 * an object in a deterministic fashion.
 *
 * @param {string} signature base58 signature, like one created with sign()
 * @param {Uint8Array} bytes byte array to verify
 * @param {string} publicKey public key corresponding to the private key used to create the signature (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {boolean} true if signature was created by signing data with the private key corresponding to publicKey
 */
export declare function verifyBytes(signature: string, bytes: Uint8Array, publicKey: string, encoding?: 'base58' | 'pem'): boolean;
//# sourceMappingURL=verify.d.ts.map