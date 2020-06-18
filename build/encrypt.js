"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.encrypt = void 0;
var crypto_1 = require("crypto");
var fast_json_stable_stringify_1 = __importDefault(require("fast-json-stable-stringify"));
var bs58_1 = __importDefault(require("bs58"));
function encrypt(did, publicKey, data) {
    var stringifiedData = fast_json_stable_stringify_1.default(data);
    // create aes key
    var key = crypto_1.randomBytes(32);
    var iv = crypto_1.randomBytes(16);
    var algorithm = 'aes-256-cbc';
    var cipher = crypto_1.createCipheriv(algorithm, key, iv);
    // encrypt data with aes key
    cipher.update(stringifiedData);
    var encrypted = cipher.final();
    // encrypt aes key with public key
    var encryptedIv = crypto_1.publicEncrypt(publicKey, iv);
    var encryptedKey = crypto_1.publicEncrypt(publicKey, key);
    var encryptedAlgo = crypto_1.publicEncrypt(publicKey, Buffer.from(algorithm));
    return {
        data: bs58_1.default.encode(encrypted),
        key: {
            iv: bs58_1.default.encode(encryptedIv),
            key: bs58_1.default.encode(encryptedKey),
            algorithm: bs58_1.default.encode(encryptedAlgo),
            did: did
        }
    };
}
exports.encrypt = encrypt;
