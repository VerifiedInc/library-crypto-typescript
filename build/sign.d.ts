/**
 * @deprecated prefer signBytes
 * Used to encode the provided data object into a string prior to signing.
 * Should only be used if dealing with projects can ensure identical data object string encoding.
 * For this reason it deprecated in favor of signBytes for Protobufs for objects that need to be signed and verified.
 *
 * @param {*} data data to sign (JSON-serializable object)
 * @param {string} privateKey private key to sign with (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {string} signature with privateKey over data encoded as a base58 string
 */
export declare function sign(data: unknown, privateKey: string, encoding?: 'base58' | 'pem'): string;
/**
 * Used to sign a byte array. Exported thanks to the property of Protobuf's ability to encode to bytes and decode back
 * an object in a deterministic fashion.
 *
 * @param {Uint8Array} bytes bytes array to sign
 * @param {string} privateKey private key to sign with (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {string} signature with privateKey over data encoded as a base58 string
 */
export declare function signBytes(bytes: Uint8Array, privateKey: string, encoding?: 'base58' | 'pem'): string;
/**
 * Used to sign a byte array. Exported thanks to the property of Protobuf's ability to encode to bytes and decode back
 * an object in a deterministic fashion.
 *
 * @param {Uint8Array} bytes bytes array to sign
 * @param {string} privateKey private key to sign with (pem or base58)
 * @returns {string} signature with privateKey over data encoded as a base58 string
 */
export declare function signBytesV2(bytes: Uint8Array, privateKey: string): string;
//# sourceMappingURL=sign.d.ts.map