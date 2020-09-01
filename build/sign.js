"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sign = void 0;
var crypto_1 = __importDefault(require("crypto"));
var fast_json_stable_stringify_1 = __importDefault(require("fast-json-stable-stringify"));
var bs58_1 = __importDefault(require("bs58"));
var helpers_1 = require("./helpers");
/**
 * @param {*} data data to sign (JSON-serializable object)
 * @param {string} privateKey private key to sign with (pem or base58)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {string} signature with privateKey over data encoded as a base58 string
 */
function sign(data, privateKey, encoding) {
    if (encoding === void 0) { encoding = 'pem'; }
    // serialize data as a deterministic JSON string
    var stringifiedData = fast_json_stable_stringify_1.default(data);
    var decodedPrivateKey = helpers_1.decodeKey(privateKey, encoding);
    // convert to a Buffer and sign with private key
    var buf = Buffer.from(stringifiedData);
    var signatureValueBuf = crypto_1.default.sign(null, buf, decodedPrivateKey);
    // return resulting Buffer encoded as a base58 string
    return bs58_1.default.encode(signatureValueBuf);
}
exports.sign = sign;
