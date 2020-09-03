"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.derToPem = exports.decodeKey = exports.promisifiedGenerateKeyPair = void 0;
var crypto_1 = require("crypto");
var util_1 = require("util");
var bs58_1 = __importDefault(require("bs58"));
exports.promisifiedGenerateKeyPair = util_1.promisify(crypto_1.generateKeyPair);
function decodeKey(publicKey, encoding) {
    return encoding === 'base58' ? bs58_1.default.decode(publicKey) : publicKey;
}
exports.decodeKey = decodeKey;
function derToPem(key, type) {
    if (typeof key === 'string') {
        // it's already pem
        return key;
    }
    var bs64 = key.toString('base64');
    var header = "-----BEGIN " + type.toUpperCase() + " KEY-----";
    var footer = "-----END " + type.toUpperCase() + " KEY-----";
    return header + "\n" + bs64 + "\n" + footer;
}
exports.derToPem = derToPem;
