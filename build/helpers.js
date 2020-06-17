"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.promisifiedGenerateKeyPair = void 0;
var crypto_1 = require("crypto");
var util_1 = require("util");
exports.promisifiedGenerateKeyPair = util_1.promisify(crypto_1.generateKeyPair);
