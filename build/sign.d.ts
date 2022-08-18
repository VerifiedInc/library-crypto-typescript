/**
 * Used to sign a byte array. Exported thanks to the property of Protobuf's ability to encode to bytes and decode back
 * an object in a deterministic fashion.
 *
 * @param {Uint8Array} bytes bytes array to sign
 * @param {string} privateKey private key to sign with (pem or base58)
 * @returns {string} signature with privateKey over data encoded as a base58 string
 */
export declare function signBytes(bytes: Uint8Array, privateKey: string): string;
//# sourceMappingURL=sign.d.ts.map