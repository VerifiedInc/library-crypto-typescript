"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AesString = void 0;
var crypto_1 = require("crypto");
/**
 * Class to handle aes encryption and decryption with string inputs.
 */
var AesString = /** @class */ (function () {
    function AesString(key, iv, algorithm) {
        if (key === void 0) { key = crypto_1.randomBytes(32); }
        if (iv === void 0) { iv = crypto_1.randomBytes(32); }
        if (algorithm === void 0) { algorithm = 'aes-256-cbc'; }
        this.key = key;
        this.iv = iv;
        this.algorithm = algorithm;
    }
    AesString.prototype.encrypt = function (data) {
        // create aes cipher
        var cipher = crypto_1.createCipheriv(this.algorithm, this.key, this.iv);
        // encrypt data with aes cipher
        var encrypted1 = cipher.update(data);
        var encrypted2 = cipher.final();
        var encrypted = Buffer.concat([encrypted1, encrypted2]);
        return encrypted;
    };
    AesString.prototype.decrypt = function (data) {
        // create aes cipher
        var decipher = crypto_1.createDecipheriv(this.algorithm, this.key, this.iv);
        // decrypt data with aes cipher
        var decrypted1 = decipher.update(data);
        var decrypted2 = decipher.final();
        var decrypted = Buffer.concat([decrypted1, decrypted2]);
        return decrypted;
    };
    return AesString;
}());
exports.AesString = AesString;
//# sourceMappingURL=aesString.js.map