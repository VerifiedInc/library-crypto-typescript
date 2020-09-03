/// <reference types="node" />
import { generateKeyPair } from 'crypto';
export declare const promisifiedGenerateKeyPair: typeof generateKeyPair.__promisify__;
export declare function decodeKey(publicKey: string, encoding: 'base58' | 'pem'): string | Buffer;
export declare function derToPem(key: Buffer | string, type: 'public' | 'private'): string;
