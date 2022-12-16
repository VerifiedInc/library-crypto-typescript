import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

/**
 * Class to facilitate encryption and decryption of data using AES.
 */
export class Aes {
    key: Buffer;
    iv: Buffer;
    algorithm: string;

    constructor (key: Buffer = randomBytes(32), iv: Buffer = randomBytes(16), algorithm = 'aes-256-cbc') {
      this.key = key;
      this.iv = iv;
      this.algorithm = algorithm;
    }

    /**
     * Encrypts input Uint8Array using AES.
     * @param data Uint8Array
     * @returns Buffer
     */
    encrypt (data: Uint8Array): Buffer {
      // create aes cipher
      const cipher = createCipheriv(this.algorithm, this.key, this.iv);

      // encrypt data with aes cipher
      const encrypted1 = cipher.update(data);
      const encrypted2 = cipher.final();
      const encrypted = Buffer.concat([encrypted1, encrypted2]);

      return encrypted;
    }

    /**
     * Decrypts input Uint8Array using AES.
     * @param data Uint8Array
     * @returns Buffer
     */
    decrypt (data: Uint8Array): Buffer {
      // create aes cipher
      const decipher = createDecipheriv(this.algorithm, this.key, this.iv);

      // decrypt data with aes cipher
      const decrypted1 = decipher.update(data);
      const decrypted2 = decipher.final();
      const decrypted = Buffer.concat([decrypted1, decrypted2]);

      return decrypted;
    }
}
