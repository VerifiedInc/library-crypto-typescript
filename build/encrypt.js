"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.encryptBytes = exports.encrypt = void 0;
var crypto_1 = require("crypto");
var fast_json_stable_stringify_1 = __importDefault(require("fast-json-stable-stringify"));
var bs58_1 = __importDefault(require("bs58"));
var helpers_1 = require("./helpers");
var CryptoError_1 = require("./types/CryptoError");
/**
 * Used to encode the provided data object into a string prior to encrypting.
 * Should only be used if dealing with projects can ensure identical data object string encoding.
 * For this reason it deprecated in favor of encryptBytes with Protobufs for objects that need to be encrypted.
 *
 * @param {string} did the DID and key identifier fragment resolving to the public key
 * @param {string} publicKey RSA public key (pem or base58)
 * @param {object} data data to encrypt (JSON-serializable object)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {EncryptedData} contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                          key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 */
function encrypt(did, publicKey, data, encoding) {
    if (encoding === void 0) { encoding = 'pem'; }
    try {
        // serialize data as a deterministic JSON string
        var stringifiedData = fast_json_stable_stringify_1.default(data);
        return encryptBytes(did, publicKey, stringifiedData, encoding);
    }
    catch (e) {
        throw new CryptoError_1.CryptoError(e.message, e.code);
    }
}
exports.encrypt = encrypt;
/**
 *  Used to encrypt a byte array. Exposed for use with Protobuf's byte arrays.
 *
 * @param {string} did the DID and key identifier fragment resolving to the public key
 * @param {string} publicKey RSA public key (pem or base58)
 * @param {BinaryLike} data data to encrypt
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {EncryptedData} contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                          key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 */
function encryptBytes(did, publicKey, data, encoding) {
    if (encoding === void 0) { encoding = 'pem'; }
    try {
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
        var encrypted1 = cipher.update(data);
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
    catch (e) {
        throw new CryptoError_1.CryptoError(e.message, e.code);
    }
}
exports.encryptBytes = encryptBytes;
//# sourceMappingURL=encrypt.js.map