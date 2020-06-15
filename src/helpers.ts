import { generateKeyPair } from 'crypto';
import { promisify } from 'util';

export const promisifiedGenerateKeyPair = promisify(generateKeyPair);
