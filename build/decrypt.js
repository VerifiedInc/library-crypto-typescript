"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.decrypt = void 0;
var crypto_1 = require("crypto");
var bs58_1 = __importDefault(require("bs58"));
function decrypt(privateKey, encryptedData) {
    var data = encryptedData.data;
    var _a = encryptedData.key, iv = _a.iv, key = _a.key, algorithm = _a.algorithm;
    // decode aes key info and encrypted data from base58 to Buffers
    var decodedEncryptedIv = bs58_1.default.decode(iv);
    var decodedEncryptedKey = bs58_1.default.decode(key);
    var decodedEncryptedAlgorithm = bs58_1.default.decode(algorithm);
    var decodedEncryptedData = bs58_1.default.decode(data);
    // decrypt aes key info with private key
    var decryptedIv = crypto_1.privateDecrypt(privateKey, decodedEncryptedIv);
    var decryptedKey = crypto_1.privateDecrypt(privateKey, decodedEncryptedKey);
    var decryptedAlgorithm = crypto_1.privateDecrypt(privateKey, decodedEncryptedAlgorithm);
    // create aes key
    var decipher = crypto_1.createDecipheriv(decryptedAlgorithm.toString(), decryptedKey, decryptedIv);
    // decrypt data with aes key
    var decrypted1 = decipher.update(decodedEncryptedData);
    var decrypted2 = decipher.final();
    var decrypted = Buffer.concat([decrypted1, decrypted2]);
    // re-encode decrypted data as a regular utf-8 string
    var decryptedStr = decrypted.toString('utf-8');
    // parse original encoded object from decrypted json string
    return JSON.parse(decryptedStr);
}
exports.decrypt = decrypt;
