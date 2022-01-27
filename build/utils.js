"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectEncodingType = exports.getPadding = void 0;
var types_1 = require("@unumid/types");
var crypto_1 = require("crypto");
var _1 = require(".");
function getPadding(padding) {
    switch (padding) {
        case types_1.RSAPadding.PKCS: return crypto_1.constants.RSA_PKCS1_PADDING;
        case types_1.RSAPadding.OAEP: return crypto_1.constants.RSA_PKCS1_OAEP_PADDING;
        default: {
            throw new _1.CryptoError('Unrecognized RSA padding.');
        }
    }
}
exports.getPadding = getPadding;
/**
 * Helper to detect the key encoding type.
 *
 * This check could probably be made more robust, however this works for now.
 * @param key
 * @returns
 */
function detectEncodingType(key) {
    if (key.startsWith('-----BEGIN PUBLIC KEY-----')) {
        return 'pem';
    }
    else if (key.startsWith('-----BEGIN RSA PUBLIC KEY-----')) {
        return 'pem';
    }
    else if (key.startsWith('-----BEGIN CERTIFICATE-----')) {
        return 'pem';
    }
    else if (key.startsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----')) {
        return 'pem';
    }
    else if (key.startsWith('-----BEGIN PRIVATE KEY-----')) {
        return 'pem';
    }
    else if (key.startsWith('-----BEGIN RSA PRIVATE KEY-----')) {
        return 'pem';
    }
    else if (key.startsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----')) {
        return 'pem';
    }
    else if (key.startsWith('-----BEGIN CERTIFICATE REQUEST-----')) {
        return 'pem';
    }
    else if (key.startsWith('-----BEGIN DSA PRIVATE KEY-----')) {
        return 'pem';
    }
    else if (key.startsWith('-----BEGIN EC PRIVATE KEY-----')) {
        return 'pem';
    }
    else if (key.startsWith('-----BEGIN DSA PRIVATE KEY-----')) {
        return 'pem';
    }
    else if (key.startsWith('-----BEGIN EC PRIVATE KEY-----')) {
        return 'pem';
    }
    else if (key.startsWith('-----BEGIN PRIVATE KEY-----')) {
        return 'pem';
    }
    else if (key.startsWith('-----BEGIN RSA PRIVATE KEY-----')) {
        return 'pem';
    }
    else if (key.startsWith('-----BEGIN DSA PRIVATE KEY-----')) {
        return 'pem';
    }
    else if (key.startsWith('-----BEGIN EC PRIVATE KEY-----')) {
        return 'pem';
    }
    return 'base58';
}
exports.detectEncodingType = detectEncodingType;
//# sourceMappingURL=utils.js.map