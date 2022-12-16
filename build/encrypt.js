"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.encryptBytesHelper = exports.encryptBytes = void 0;
var crypto_1 = require("crypto");
var types_1 = require("@unumid/types");
var helpers_1 = require("./helpers");
var CryptoError_1 = require("./types/CryptoError");
var utils_1 = require("./utils");
var aes_1 = require("./aes");
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
    return encryptBytesHelper(did, publicKey, data, encoding, rsaPadding);
}
exports.encryptBytes = encryptBytes;
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
        var decodedPublicKey = (0, helpers_1.decodeKey)(publicKey, encoding);
        // node can only encrypt with pem-encoded keys
        var publicKeyPem = (0, helpers_1.derToPem)(decodedPublicKey, 'public');
        // create aes key, iv and Aes instance for encryption
        var key = (0, crypto_1.randomBytes)(32);
        var iv = (0, crypto_1.randomBytes)(16);
        var algorithm = 'aes-256-cbc';
        var aes = new aes_1.Aes(key, iv, algorithm);
        // encrypt data with aes key
        var encrypted = aes.encrypt(data);
        // we need to use a key object to set non-default padding
        // for interoperability with android/ios/webcrypto cryptography implementations
        var publicKeyObj = {
            key: publicKeyPem,
            padding: (0, utils_1.getPadding)(rsaPadding)
        };
        // encrypt aes key with public key
        var encryptedIv = (0, crypto_1.publicEncrypt)(publicKeyObj, iv);
        var encryptedKey = (0, crypto_1.publicEncrypt)(publicKeyObj, key);
        var encryptedAlgo = (0, crypto_1.publicEncrypt)(publicKeyObj, Buffer.from(algorithm));
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
//# sourceMappingURL=encrypt.js.map