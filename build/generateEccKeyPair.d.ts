import { KeyPair } from './types';
export declare function generateEccKeyPair(encoding?: 'base58' | 'pem'): Promise<KeyPair>;
export declare function generateEccPemKeyPair(): Promise<KeyPair>;
export declare function generateEccBase58KeyPair(): Promise<KeyPair>;
