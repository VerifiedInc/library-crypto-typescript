"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.encrypt = void 0;
var crypto_1 = require("crypto");
var fast_json_stable_stringify_1 = __importDefault(require("fast-json-stable-stringify"));
var bs58_1 = __importDefault(require("bs58"));
function encrypt(publicKey, data) {
    var stringifiedData = fast_json_stable_stringify_1.default(data);
    var dataBuf = Buffer.from(stringifiedData);
    var encryptedBuf = crypto_1.publicEncrypt(publicKey, dataBuf);
    return bs58_1.default.encode(encryptedBuf);
}
exports.encrypt = encrypt;
