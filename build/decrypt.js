"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decryptBytes = void 0;
var crypto_1 = require("crypto");
var types_1 = require("@unumid/types");
var helpers_1 = require("./helpers");
var CryptoError_1 = require("./types/CryptoError");
var utils_1 = require("./utils");
/**
 * Used to decrypt a byte array. Exposed for use with Protobuf's byte arrays.
 *
 * @param {string} privateKey RSA private key (pem or base58) corresponding to the public key used for encryption
 * @param {EncryptedData} encryptedData EncryptedData object, like one returned from encrypt()
 *                                      contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                                      key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 * @returns {object} the decrypted object
 */
function decryptBytes(privateKey, encryptedData) {
    if (!privateKey) {
        throw new CryptoError_1.CryptoError('Private key is missing');
    }
    // detect key encoding type
    var encoding = utils_1.detectEncodingType(privateKey);
    return _decryptBytes(privateKey, encryptedData, encoding);
}
exports.decryptBytes = decryptBytes;
/**
 * Used to decrypt a byte array. Exposed for use with Protobuf's byte arrays.
 *
 * @param {string} privateKey RSA private key (pem or base58) corresponding to the public key used for encryption
 * @param {EncryptedData} encryptedData EncryptedData object, like one returned from encrypt()
 *                                      contains the encrypted data as a base58 string plus RSA-encrypted/base58-encoded
 *                                      key, iv, and algorithm information needed to recreate the AES key actually used for encryption
 * @param {string} encoding the encoding used for the publicKey ('base58' or 'pem', default 'pem')
 * @returns {object} the decrypted object
 */
function _decryptBytes(privateKey, encryptedData, encoding) {
    if (encoding === void 0) { encoding = 'pem'; }
    try {
        var data = encryptedData.data;
        var _a = encryptedData.key, iv = _a.iv, key = _a.key, algorithm = _a.algorithm;
        // decode the private key, if necessary
        var decodedPrivateKey = helpers_1.decodeKey(privateKey, encoding);
        // node can only decrypt with pem-encoded keys
        var privateKeyPem = helpers_1.derToPem(decodedPrivateKey, 'private');
        // decode aes key info and encrypted data from base58 to Buffers
        var decodedEncryptedIv = Buffer.from(iv, 'base64');
        var decodedEncryptedKey = Buffer.from(key, 'base64');
        var decodedEncryptedAlgorithm = Buffer.from(algorithm, 'base64');
        var decodedEncryptedData = Buffer.from(data, 'base64');
        // we need to use a key object to set non-default padding
        // for interoperability with android/ios/webcrypto cryptography implementations
        var privateKeyObj = {
            key: privateKeyPem,
            padding: utils_1.getPadding(encryptedData.rsaPadding || types_1.RSAPadding.PKCS)
        };
        // decrypt aes key info with private key
        var decryptedIv = crypto_1.privateDecrypt(privateKeyObj, decodedEncryptedIv);
        var decryptedKey = crypto_1.privateDecrypt(privateKeyObj, decodedEncryptedKey);
        var decryptedAlgorithm = crypto_1.privateDecrypt(privateKeyObj, decodedEncryptedAlgorithm);
        // create aes key
        var decipher = crypto_1.createDecipheriv(decryptedAlgorithm.toString(), decryptedKey, decryptedIv);
        // decrypt data with aes key
        var decrypted1 = decipher.update(decodedEncryptedData);
        var decrypted2 = decipher.final();
        var decrypted = Buffer.concat([decrypted1, decrypted2]);
        return decrypted;
    }
    catch (e) {
        var cryptoError = e;
        throw new CryptoError_1.CryptoError(cryptoError.message, cryptoError.code);
    }
}
//# sourceMappingURL=decrypt.js.map