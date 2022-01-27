import { RSAPadding } from '@unumid/types';
export declare function getPadding(padding: RSAPadding): number;
/**
 * Helper to detect the key encoding type.
 *
 * This check could probably be made more robust, however this works for now.
 * @param key
 * @returns
 */
export declare function detectEncodingType(key: string): 'base58' | 'pem';
//# sourceMappingURL=utils.d.ts.map