"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Aes = void 0;
var crypto_1 = require("crypto");
var Aes = /** @class */ (function () {
    function Aes(key, iv, algorithm) {
        if (key === void 0) { key = crypto_1.randomBytes(32); }
        if (iv === void 0) { iv = crypto_1.randomBytes(32); }
        if (algorithm === void 0) { algorithm = 'aes-256-cbc'; }
        this.key = key;
        this.iv = iv;
        this.algorithm = algorithm;
    }
    Aes.prototype.encrypt = function (data) {
        var cipher = crypto_1.createCipheriv(this.algorithm, this.key, this.iv);
        // encrypt data with aes key
        var encrypted1 = cipher.update(data);
        var encrypted2 = cipher.final();
        var encrypted = Buffer.concat([encrypted1, encrypted2]);
        return encrypted;
    };
    Aes.prototype.decrypt = function (data) {
        // create aes key
        var decipher = crypto_1.createDecipheriv(this.algorithm, this.key, this.iv);
        // decrypt data with aes key
        var decrypted1 = decipher.update(data);
        var decrypted2 = decipher.final();
        var decrypted = Buffer.concat([decrypted1, decrypted2]);
        return decrypted;
    };
    return Aes;
}());
exports.Aes = Aes;
//# sourceMappingURL=aes.js.map