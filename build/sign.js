"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sign = void 0;
var crypto_1 = __importDefault(require("crypto"));
var fast_json_stable_stringify_1 = __importDefault(require("fast-json-stable-stringify"));
var bs58_1 = __importDefault(require("bs58"));
function sign(data, privateKey) {
    var stringifiedData = fast_json_stable_stringify_1.default(data);
    var buf = Buffer.from(stringifiedData);
    var signatureValueBuf = crypto_1.default.sign(null, buf, privateKey);
    return bs58_1.default.encode(signatureValueBuf);
}
exports.sign = sign;
