"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.decrypt = void 0;
var crypto_1 = require("crypto");
var bs58_1 = __importDefault(require("bs58"));
function decrypt(privateKey, encrypted) {
    var encryptedBuf = bs58_1.default.decode(encrypted);
    var decryptedBuf = crypto_1.privateDecrypt(privateKey, encryptedBuf);
    var decryptedStr = decryptedBuf.toString();
    return JSON.parse(decryptedStr);
}
exports.decrypt = decrypt;
