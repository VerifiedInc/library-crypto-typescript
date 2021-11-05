"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getPadding = void 0;
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
//# sourceMappingURL=utils.js.map