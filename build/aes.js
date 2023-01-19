"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Aes = void 0;
var crypto_1 = require("crypto");
/**
 * Class to facilitate encryption and decryption of data using AES.
 * Note: that the IV attribute is not a class variable because it ought to be unique for each encrypt call for the same class instance (aka same key).
 */
var Aes = /** @class */ (function () {
    function Aes(key, algorithm) {
        if (key === void 0) { key = (0, crypto_1.randomBytes)(32); }
        if (algorithm === void 0) { algorithm = 'aes-256-cbc'; }
        this.key = key;
        this.algorithm = algorithm;
    }
    /**
     * Encrypts input Uint8Array using AES.
     * @param data Uint8Array
     * @param iv Uint8Array
     * @returns Buffer
     */
    Aes.prototype.encrypt = function (data, iv) {
        // create aes cipher
        var cipher = (0, crypto_1.createCipheriv)(this.algorithm, this.key, iv);
        // encrypt data with aes cipher
        var encrypted1 = cipher.update(data);
        var encrypted2 = cipher.final();
        var encrypted = Buffer.concat([encrypted1, encrypted2]);
        return encrypted;
    };
    /**
     * Decrypts input Uint8Array using AES.
     * @param data Uint8Array
     * @param iv Uint8Array
     * @returns Buffer
     */
    Aes.prototype.decrypt = function (data, iv) {
        // create aes cipher
        var decipher = (0, crypto_1.createDecipheriv)(this.algorithm, this.key, iv);
        // decrypt data with aes cipher
        var decrypted1 = decipher.update(data);
        var decrypted2 = decipher.final();
        var decrypted = Buffer.concat([decrypted1, decrypted2]);
        return decrypted;
    };
    /**
     * Helper function to generate a random byte IV.
     * @returns Buffer
     */
    Aes.prototype.generateIv = function (bytes) {
        if (bytes === void 0) { bytes = 16; }
        return (0, crypto_1.randomBytes)(bytes);
    };
    return Aes;
}());
exports.Aes = Aes;
//# sourceMappingURL=aes.js.map