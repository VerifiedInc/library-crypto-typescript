"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verify = void 0;
var crypto_1 = __importDefault(require("crypto"));
var fast_json_stable_stringify_1 = __importDefault(require("fast-json-stable-stringify"));
var bs58_1 = __importDefault(require("bs58"));
var helpers_1 = require("./helpers");
/**
 * @param {string} signature base58 signature, like one created with sign()
 * @param {any} data data to verify (JSON-serializable object)
 * @param {string} publicKey public key corresponding to the private key used to create the signature (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {boolean} true if signature was created by signing data with the private key corresponding to publicKey
 */
function verify(signature, data, publicKey, encoding) {
    if (encoding === void 0) { encoding = 'pem'; }
    // serialize data as a deterministic JSON string
    var stringifiedData = fast_json_stable_stringify_1.default(data);
    // decode public key if necessary
    var decodedPublicKey = helpers_1.decodeKey(publicKey, encoding);
    // convert stringified data to a Buffer
    var dataBuf = Buffer.from(stringifiedData);
    // decode signature from base58 to a Buffer
    var signatureBuf = bs58_1.default.decode(signature);
    // if we pass the key to crypto.verify as a buffer, it will assume pem format
    // we need to convert it to a KeyObject first in order to use der formatted keys
    // const format = encoding === 'pem' ? 'pem' : 'der';
    var format = 'der';
    var type = encoding === 'pem' ? 'pkcs1' : 'spki';
    var publicKeyObj = crypto_1.default.createPublicKey({ key: decodedPublicKey, format: format, type: type });
    // verifiy signature with the public key and return whether it succeeded
    var result = crypto_1.default.verify(null, dataBuf, publicKeyObj, signatureBuf);
    return result;
}
exports.verify = verify;
//# sourceMappingURL=verify.js.map