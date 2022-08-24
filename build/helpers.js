"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.derToPem = exports.decodeKey = exports.promisifiedGenerateKeyPair = void 0;
var crypto_1 = require("crypto");
var util_1 = require("util");
exports.promisifiedGenerateKeyPair = util_1.promisify(crypto_1.generateKeyPair);
function decodeKey(publicKey, encoding) {
    return encoding === 'base58' ? Buffer.from(publicKey, 'base64') : publicKey;
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
//# sourceMappingURL=helpers.js.map