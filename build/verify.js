"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verify = void 0;
var crypto_1 = __importDefault(require("crypto"));
var fast_json_stable_stringify_1 = __importDefault(require("fast-json-stable-stringify"));
var bs58_1 = __importDefault(require("bs58"));
function verify(signature, data, publicKey) {
    var stringifiedData = fast_json_stable_stringify_1.default(data);
    var dataBuf = Buffer.from(stringifiedData);
    var signatureBuf = bs58_1.default.decode(signature);
    var result = crypto_1.default.verify(null, dataBuf, publicKey, signatureBuf);
    return result;
}
exports.verify = verify;
