/**
 * Class to encapsulate custom errors.
 */
export class CryptoError extends Error {
    code: number;

    constructor (errMsg: string, code: number, stack?: string) {
      super();
      this.name = 'CryptoError';
      this.message = errMsg;
      this.code = code;
      this.stack = stack;
    }
}
