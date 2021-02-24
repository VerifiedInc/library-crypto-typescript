"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.CryptoError = void 0;
/**
 * Class to encapsulate custom errors.
 */
var CryptoError = /** @class */ (function (_super) {
    __extends(CryptoError, _super);
    function CryptoError(errMsg, code, stack) {
        var _this = _super.call(this) || this;
        _this.name = 'CryptoError';
        _this.message = errMsg;
        _this.code = code;
        _this.stack = stack;
        return _this;
    }
    return CryptoError;
}(Error));
exports.CryptoError = CryptoError;
//# sourceMappingURL=errors.js.map