import { EncryptedData } from './types';
export declare function encrypt(did: string, publicKey: string, data: Record<string, unknown>): EncryptedData;
