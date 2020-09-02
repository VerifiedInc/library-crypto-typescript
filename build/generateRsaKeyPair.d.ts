import { KeyPair } from './types';
export declare function generateRsaKeyPair(encoding?: 'base58' | 'pem'): Promise<KeyPair>;
export declare function generateRsaPemKeyPair(): Promise<KeyPair>;
export declare function generateRsaBase58KeyPair(): Promise<KeyPair>;
