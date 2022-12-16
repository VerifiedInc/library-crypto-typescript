"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyBytesHelper = exports.verifyBytes = void 0;
var crypto_1 = __importDefault(require("crypto"));
var helpers_1 = require("./helpers");
var CryptoError_1 = require("./types/CryptoError");
/**
 * Used to verify a byte array. The new defacto verify function thanks to the property of Protobuf's ability to encode to bytes and decode back
 * an object in a deterministic fashion.
 *
 * @param {string} signature base58 signature, like one created with sign()
 * @param {Uint8Array} bytes byte array to verify
 * @param {PublicKeyInfo} publicKey PublicKeyInfo corresponding to the private key used to create the signature (pem or base58)
 * @returns {boolean} true if signature was created by signing data with the private key corresponding to publicKey
 */
function verifyBytes(signature, bytes, publicKey) {
    if (!publicKey.publicKey) {
        throw new CryptoError_1.CryptoError('Public key is missing');
    }
    if (!publicKey.encoding) {
        throw new CryptoError_1.CryptoError('Public key encoding is missing');
    }
    return verifyBytesHelper(signature, bytes, publicKey.publicKey, publicKey.encoding);
}
exports.verifyBytes = verifyBytes;
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
function verifyBytesHelper(signature, bytes, publicKey, encoding) {
    if (encoding === void 0) { encoding = 'pem'; }
    try {
        // decode public key if necessary
        var decodedPublicKey = (0, helpers_1.decodeKey)(publicKey, encoding);
        // decode signature from base58 to a Buffer
        var signatureBytes = Buffer.from(signature, 'base64');
        // if we pass the key to crypto.verify as a buffer, it will assume pem format
        // we need to convert it to a KeyObject first in order to use der formatted keys
        var format = encoding === 'pem' ? 'pem' : 'der';
        var type = encoding === 'pem' ? 'pkcs1' : 'spki';
        var publicKeyObj = crypto_1.default.createPublicKey({ key: decodedPublicKey, format: format, type: type });
        // verify the signature with the public key and return whether it succeeded
        var result = crypto_1.default.verify(null, bytes, publicKeyObj, signatureBytes);
        return result;
    }
    catch (e) {
        throw new CryptoError_1.CryptoError(e.message, e.code);
    }
}
exports.verifyBytesHelper = verifyBytesHelper;
//# sourceMappingURL=verify.js.map