"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Aes = void 0;
var crypto_1 = require("crypto");
/**
 * Class to facilitate encryption and decryption of data using AES.
 */
var Aes = /** @class */ (function () {
    function Aes(key, iv, algorithm) {
        if (key === void 0) { key = (0, crypto_1.randomBytes)(32); }
        if (iv === void 0) { iv = (0, crypto_1.randomBytes)(16); }
        if (algorithm === void 0) { algorithm = 'aes-256-cbc'; }
        this.key = key;
        this.iv = iv;
        this.algorithm = algorithm;
    }
    /**
     * Encrypts input Uint8Array using AES.
     * @param data Uint8Array
     * @returns Buffer
     */
    Aes.prototype.encrypt = function (data) {
        // create aes cipher
        var cipher = (0, crypto_1.createCipheriv)(this.algorithm, this.key, this.iv);
        // encrypt data with aes cipher
        var encrypted1 = cipher.update(data);
        var encrypted2 = cipher.final();
        var encrypted = Buffer.concat([encrypted1, encrypted2]);
        return encrypted;
    };
    /**
     * Decrypts input Uint8Array using AES.
     * @param data Uint8Array
     * @returns Buffer
     */
    Aes.prototype.decrypt = function (data) {
        // create aes cipher
        var decipher = (0, crypto_1.createDecipheriv)(this.algorithm, this.key, this.iv);
        // decrypt data with aes cipher
        var decrypted1 = decipher.update(data);
        var decrypted2 = decipher.final();
        var decrypted = Buffer.concat([decrypted1, decrypted2]);
        return decrypted;
    };
    return Aes;
}());
exports.Aes = Aes;
//# sourceMappingURL=aes.js.map