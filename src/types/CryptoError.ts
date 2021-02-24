/**
 * Class to encapsulate custom CryptoError.
 */
export class CryptoError extends Error {
    code: number | undefined; // place holder if want to codify the errors

    constructor (message: string, code?: number) {
      super(message);
      this.code = code;

      // see: typescriptlang.org/docs/handbook/release-notes/typescript-2-2.html
      Object.setPrototypeOf(this, new.target.prototype); // restore prototype chain
      this.name = CryptoError.name; // stack traces display correctly now
    }
}
