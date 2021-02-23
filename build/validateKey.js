"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateKeyInfo = void 0;
var crypto_1 = __importDefault(require("crypto"));
var helpers_1 = require("./helpers");
/**
 * @param {string} key key (pem or base58)
 * @param {string} encoding the encoding used for the key ('base58' or 'pem', default 'pem')
 * @returns {boolean} true if valid key information
 */
function validateKeyInfo(key, encoding) {
    if (encoding === void 0) { encoding = 'pem'; }
    // decode public key if necessary
    var decodedKey = helpers_1.decodeKey(key, encoding);
    // if we pass the key to crypto.verify as a buffer, it will assume pem format
    // we need to convert it to a KeyObject first in order to use der formatted keys
    var format = encoding === 'pem' ? 'pem' : 'der';
    var type = encoding === 'pem' ? 'pkcs1' : 'spki';
    crypto_1.default.createPublicKey({ key: decodedKey, format: format, type: type });
    // an exception would be thrown if invalid
    return true;
}
exports.validateKeyInfo = validateKeyInfo;
//# sourceMappingURL=validateKey.js.map