/**
 * Class to encapsulate custom CryptoError.
 */
export class CryptoError extends Error {
    code: number;

    constructor (message: string, code: number, stack?: string) {
      super(message);
      this.code = code;

      // see: typescriptlang.org/docs/handbook/release-notes/typescript-2-2.html
      Object.setPrototypeOf(this, new.target.prototype); // restore prototype chain
      this.name = CryptoError.name; // stack traces display correctly now
    }
}
