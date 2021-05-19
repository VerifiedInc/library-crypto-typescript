/// <reference types="node" />
/**
 * Used to encode the provided data object into a string prior to signing.
 * Should only be used if dealing with projects that run in node's V8 runtime so the string encoding can be replicated.
 * For this reason it deprecated in favor of using protobufs for objects that need to be signed and leveraging signBytes.
 *
 * @param {*} data data to sign (JSON-serializable object)
 * @param {string} privateKey private key to sign with (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {string} signature with privateKey over data encoded as a base58 string
 */
export declare function sign(data: unknown, privateKey: string, encoding?: 'base58' | 'pem'): string;
/**
 * Used to sign a byte array. Exported thanks to the use of Protobufs and being able to encode to bytes and decode back
 * an object in a deterministic fashion.
 *
 * @param {*} bytes bytes array to sign
 * @param {string} privateKey private key to sign with (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {string} signature with privateKey over data encoded as a base58 string
 */
export declare function signBytes(bytes: Buffer, privateKey: string, encoding?: 'base58' | 'pem'): string;
//# sourceMappingURL=sign.d.ts.map