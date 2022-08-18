"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.encryptBytes = exports.encryptBytesHelper = exports.encrypt = void 0;
var crypto_1 = require("crypto");
var fast_json_stable_stringify_1 = __importDefault(require("fast-json-stable-stringify"));
var types_1 = require("@unumid/types");
var helpers_1 = require("./helpers");
var CryptoError_1 = require("./types/CryptoError");
var utils_1 = require("./utils");
/**
 * @deprecated prefer encryptBytes
 * Used to encode the provided data object into a string prior to encrypting.
 * Should only be used if dealing with projects can ensure identical data object string encoding.
 * For this reason it deprecated in favor of encryptBytes with Protobufs for objects that need to be encrypted.
 *
 * @param {string} did the DID and key identifier fragment resolving to the public key
 * @param {string} publicKey RSA public key (pem or base58)
 * @param {object} data data to encrypt (JSON-serializable object)
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @param { RSAPadding} rsaPadding padding to use for RSA encryption (PKCS1 v1.5 or OAEP).
 *                                 Necessary because web crypto only supports OAEP padding for decryption,
 *                                 and cannot decrypt data encrypted with PKCS1 v1.5 padding.
 *                                 Defaults to PKCS to preserve backwards compatibility,
 *                                 as older public keys (from before we used web crypto) do not specify a padding.
 * @returns {EncryptedData} contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                          key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 */
function encrypt(did, publicKey, data, encoding, rsaPadding) {
    if (encoding === void 0) { encoding = 'pem'; }
    if (rsaPadding === void 0) { rsaPadding = types_1.RSAPadding.PKCS; }
    try {
        // serialize data as a deterministic JSON string
        var stringifiedData = fast_json_stable_stringify_1.default(data);
        return encryptBytesHelper(did, publicKey, stringifiedData, encoding, rsaPadding);
    }
    catch (e) {
        var cryptoError = e;
        throw new CryptoError_1.CryptoError(cryptoError.message, cryptoError.code);
    }
}
exports.encrypt = encrypt;
/**
 *  Helper used to encrypt a byte array. Exposed for use with Protobuf's byte arrays.
 *
 * @param {string} did the DID and key identifier fragment resolving to the public key
 * @param {string} publicKey RSA public key (pem or base58)
 * @param {BinaryLike} data data to encrypt
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {EncryptedData} contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                          key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 */
function encryptBytesHelper(did, publicKey, data, encoding, rsaPadding) {
    if (encoding === void 0) { encoding = 'pem'; }
    if (rsaPadding === void 0) { rsaPadding = types_1.RSAPadding.PKCS; }
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
        // for interoperability with android/ios/webcrypto cryptography implementations
        var publicKeyObj = {
            key: publicKeyPem,
            padding: utils_1.getPadding(rsaPadding)
        };
        // encrypt aes key with public key
        var encryptedIv = crypto_1.publicEncrypt(publicKeyObj, iv);
        var encryptedKey = crypto_1.publicEncrypt(publicKeyObj, key);
        var encryptedAlgo = crypto_1.publicEncrypt(publicKeyObj, Buffer.from(algorithm));
        // return EncryptedData object with encrypted data and aes key info
        return {
            data: encrypted.toString('base64'),
            key: {
                iv: encryptedIv.toString('base64'),
                key: encryptedKey.toString('base64'),
                algorithm: encryptedAlgo.toString('base64'),
                did: did
            },
            rsaPadding: rsaPadding
        };
    }
    catch (e) {
        var cryptoError = e;
        throw new CryptoError_1.CryptoError(cryptoError.message, cryptoError.code);
    }
}
exports.encryptBytesHelper = encryptBytesHelper;
/**
 *  Used to encrypt a byte array. Exposed for use with Protobuf's byte arrays.
 *
 * @param {string} did the DID and key identifier fragment resolving to the public key
 * @param {PublicKeyInfo} publicKey RSA publicKeyInfo
 * @param {BinaryLike} data data to encrypt
 * @returns {EncryptedData} contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                          key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 */
function encryptBytes(did, publicKeyInfo, data) {
    var publicKey = publicKeyInfo.publicKey, encoding = publicKeyInfo.encoding, rsaPadding = publicKeyInfo.rsaPadding;
    if (!publicKey) {
        throw new CryptoError_1.CryptoError('Public key is missing');
    }
    // checking even though a default value is in the helper because all PublicKeyInfo objects ought to have it set
    if (!encoding) {
        throw new CryptoError_1.CryptoError('Public key encoding is missing');
    }
    // Not checking because it's a new attribute and there is a default value in the helper.
    // if (!rsaPadding) {
    //   throw new CryptoError('Public key rsaPadding is missing');
    // }
    return encryptBytesHelper(did, publicKey, data, encoding, rsaPadding);
}
exports.encryptBytes = encryptBytes;
//# sourceMappingURL=encrypt.js.map