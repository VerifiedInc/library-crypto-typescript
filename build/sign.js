"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.signBytes = void 0;
var crypto_1 = __importDefault(require("crypto"));
var helpers_1 = require("./helpers");
var CryptoError_1 = require("./types/CryptoError");
var utils_1 = require("./utils");
/**
 * Used to sign a byte array. Exported thanks to the property of Protobuf's ability to encode to bytes and decode back
 * an object in a deterministic fashion.
 *
 * @param {Uint8Array} bytes bytes array to sign
 * @param {string} privateKey private key to sign with (pem or base58)
 * @returns {string} signature with privateKey over data encoded as a base58 string
 */
function signBytes(bytes, privateKey) {
    if (!privateKey) {
        throw new CryptoError_1.CryptoError('Private key is missing');
    }
    // detect key encoding type
    var encoding = utils_1.detectEncodingType(privateKey);
    return _signBytes(bytes, privateKey, encoding);
}
exports.signBytes = signBytes;
/**
 * Used to sign a byte array. Exported thanks to the property of Protobuf's ability to encode to bytes and decode back
 * an object in a deterministic fashion.
 *
 * @param {Uint8Array} bytes bytes array to sign
 * @param {string} privateKey private key to sign with (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {string} signature with privateKey over data encoded as a base58 string
 */
function _signBytes(bytes, privateKey, encoding) {
    if (encoding === void 0) { encoding = 'pem'; }
    try {
        var decodedPrivateKey = helpers_1.decodeKey(privateKey, encoding);
        // if we pass the key to crypto.sign as a buffer, it will assume pem format
        // we need to convert it to a KeyObject first in order to use der formatted keys
        var format = encoding === 'pem' ? 'pem' : 'der';
        var type = encoding === 'pem' ? 'pkcs1' : 'pkcs8';
        var privateKeyObj = crypto_1.default.createPrivateKey({ key: decodedPrivateKey, format: format, type: type });
        var signatureValueBuf = crypto_1.default.sign(null, bytes, privateKeyObj);
        // return resulting Buffer encoded as a base58 string
        return signatureValueBuf.toString('base64');
    }
    catch (e) {
        throw new CryptoError_1.CryptoError(e.message, e.code);
    }
}
//# sourceMappingURL=sign.js.map