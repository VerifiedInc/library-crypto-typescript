"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.encrypt = void 0;
var crypto_1 = require("crypto");
var fast_json_stable_stringify_1 = __importDefault(require("fast-json-stable-stringify"));
var bs58_1 = __importDefault(require("bs58"));
var helpers_1 = require("./helpers");
/**
 * @param {string} did the DID and key identifier fragment resolving to the public key
 * @param {string} publicKey RSA public key (pem or base58)
 * @param {object} data data to encrypt (JSON-serializable object)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {EncryptedData} contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                          key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 */
function encrypt(did, publicKey, data, encoding) {
    if (encoding === void 0) { encoding = 'pem'; }
    // serialize data as a deterministic JSON string
    var stringifiedData = fast_json_stable_stringify_1.default(data);
    // decode the public key, if necessary
    var decodedPublicKey = helpers_1.decodeKey(publicKey, encoding);
    // node can only encrypt with pem-encoded keys
    var publicKeyPem = helpers_1.derToPem(decodedPublicKey, 'public');
    // create aes key for encryption
    var key = crypto_1.randomBytes(32);
    var iv = crypto_1.randomBytes(16);
    var algorithm = 'aes-256-cbc';
    var cipher = crypto_1.createCipheriv(algorithm, key, iv);
    // encrypt data with aes key
    var encrypted1 = cipher.update(stringifiedData);
    var encrypted2 = cipher.final();
    var encrypted = Buffer.concat([encrypted1, encrypted2]);
    // we need to use a key object to set non-default padding
    // for interoperability with android/ios cryptography implementations
    var publicKeyObj = {
        key: publicKeyPem,
        padding: crypto_1.constants.RSA_PKCS1_PADDING
    };
    // encrypt aes key with public key
    var encryptedIv = crypto_1.publicEncrypt(publicKeyObj, iv);
    var encryptedKey = crypto_1.publicEncrypt(publicKeyObj, key);
    var encryptedAlgo = crypto_1.publicEncrypt(publicKeyObj, Buffer.from(algorithm));
    // return EncryptedData object with encrypted data and aes key info
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
//# sourceMappingURL=encrypt.js.map