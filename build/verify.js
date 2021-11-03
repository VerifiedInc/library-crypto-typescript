"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyBytes = exports.verifyString = exports.verify = void 0;
var crypto_1 = __importDefault(require("crypto"));
var fast_json_stable_stringify_1 = __importDefault(require("fast-json-stable-stringify"));
var bs58_1 = __importDefault(require("bs58"));
var helpers_1 = require("./helpers");
var CryptoError_1 = require("./types/CryptoError");
/**
 * Used to verify the provide data object against a provided Base58 encode signature.
 * Should only be used if dealing with projects can ensure identical data object string encoding.
 * For this reason it deprecated in favor of verifyBytes for Protobufs for objects that need to be signed and leveraging signBytes.
 *
 * @param {string} signature base58 signature, like one created with sign()
 * @param {any} data data to verify (JSON-serializable object)
 * @param {string} publicKey public key corresponding to the private key used to create the signature (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {boolean} true if signature was created by signing data with the private key corresponding to publicKey
 */
function verify(signature, data, publicKey, encoding) {
    if (encoding === void 0) { encoding = 'pem'; }
    try {
        // serialize data as a deterministic JSON string
        var stringifiedData = (0, fast_json_stable_stringify_1.default)(data);
        return verifyString(signature, stringifiedData, publicKey, encoding);
    }
    catch (e) {
        throw new CryptoError_1.CryptoError(e.message, e.code);
    }
}
exports.verify = verify;
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
function verifyString(signature, stringifiedData, publicKey, encoding) {
    if (encoding === void 0) { encoding = 'pem'; }
    try {
        // convert stringified data to a Buffer
        var dataBuf = Buffer.from(stringifiedData);
        // verifiy signature with the public key and return whether it succeeded
        return verifyBytes(signature, dataBuf, publicKey, encoding);
    }
    catch (e) {
        throw new CryptoError_1.CryptoError(e.message, e.code);
    }
}
exports.verifyString = verifyString;
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
function verifyBytes(signature, bytes, publicKey, encoding) {
    if (encoding === void 0) { encoding = 'pem'; }
    try {
        // decode public key if necessary
        var decodedPublicKey = (0, helpers_1.decodeKey)(publicKey, encoding);
        // decode signature from base58 to a Buffer
        var signatureBytes = bs58_1.default.decode(signature);
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
exports.verifyBytes = verifyBytes;
//# sourceMappingURL=verify.js.map