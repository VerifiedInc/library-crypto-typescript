"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.decrypt = void 0;
var crypto_1 = require("crypto");
var bs58_1 = __importDefault(require("bs58"));
function decrypt(privateKey, encryptedData) {
    // decode aes key info
    var _a = encryptedData.key, iv = _a.iv, key = _a.key, algorithm = _a.algorithm;
    var encryptedIv = bs58_1.default.decode(iv);
    var encryptedKey = bs58_1.default.decode(key);
    var encryptedAlgorithm = bs58_1.default.decode(algorithm);
    var decryptedIv = crypto_1.privateDecrypt(privateKey, encryptedIv);
    var decryptedKey = crypto_1.privateDecrypt(privateKey, encryptedKey);
    var decryptedAlgorithm = crypto_1.privateDecrypt(privateKey, encryptedAlgorithm);
    // create aes key
    var decipher = crypto_1.createDecipheriv(decryptedAlgorithm.toString(), decryptedKey, decryptedIv);
    // decrypt data with aes key
    decipher.update(bs58_1.default.decode(encryptedData.data));
    var decryptedStr = decipher.final('utf8');
    return JSON.parse(decryptedStr);
}
exports.decrypt = decrypt;
