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
        var decodedPublicKey = helpers_1.decodeKey(publicKey, encoding);
        // node can only encrypt with pem-encoded keys
        var publicKeyPem = helpers_1.derToPem(decodedPublicKey, 'public');
        // // create aes key for encryption
        // const key = randomBytes(32);
        // const iv = randomBytes(16);
        // const algorithm = 'aes-256-cbc';
        // const cipher = createCipheriv(algorithm, key, iv);
        // // encrypt data with aes key
        // const encrypted1 = cipher.update(data);
        // const encrypted2 = cipher.final();
        // const encrypted = Buffer.concat([encrypted1, encrypted2]);
        // const { key, iv, algorithm, encrypted } = aesEncryption(data);
        // create aes key, iv and Aes instance for encryption
        var key = crypto_1.randomBytes(32);
        var iv = crypto_1.randomBytes(16);
        var algorithm = 'aes-256-cbc';
        var aes = new aes_1.Aes(key, iv, algorithm);
        // encrypt data with aes key
        var encrypted = aes.encrypt(data);
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
// /**
//  * Function used to encrypt a byte array with aes.
//  * @returns
//  */
// export function aesEncryption (data: Uint8Array): {key: Buffer, iv: Buffer, algorithm: string, encrypted: Buffer} {
//   // create aes key for encryption
//   const key = randomBytes(32);
//   const iv = randomBytes(16);
//   const algorithm = 'aes-256-cbc';
//   // const cipher = createCipheriv(algorithm, key, iv);
//   // return aesEncryptionHelper(data, key);
//   const aes = new Aes(key, iv, algorithm);
//   // encrypt data with aes key
//   const encrypted = aes.encrypt(data);
// }
// export function aesEncryptionHelper (data: Uint8Array, key: Buffer): {key: Buffer, iv: Buffer, algorithm: string, encrypted: Buffer} {
//   // create aes iv for encryption
//   const iv = randomBytes(16);
//   const algorithm = 'aes-256-cbc';
//   const cipher = createCipheriv(algorithm, key, iv);
//   // encrypt data with aes key
//   const encrypted1 = cipher.update(data);
//   const encrypted2 = cipher.final();
//   const encrypted = Buffer.concat([encrypted1, encrypted2]);
//   return {
//     key,
//     iv,
//     algorithm,
//     encrypted
//   };
// }
//# sourceMappingURL=encrypt.js.map