# Library-Crypto-TypeScript
A helper library for common Unum ID cryptographic functions in TypeScript.

## Installation
This library is currently only available from Github. To add it to your project, run `yarn add library-crypto-typescript@https://github.com/UnumID/Library-Crypto-TypeScript.git` or add the following to the `dependencies` section of your `package.json` and run `yarn install`.
```
"library-crypto-typescript": "https://github.com/UnumID/Library-Crypto-TypeScript.git"
```

## Functionality
### generateEccKeyPair
Generates `secp256r1` private and public keys.

```typescript
() => Promise<{ privateKey: string; publicKey: string}>;
```

- arguments
  - none
- returns
  - Promise resolving to pem-encoded privateKey and publicKey

#### Usage
```typescript
import { generateEccKeyPair } from 'library-crypto-typescript';

// using async/await
const { privateKey, publicKey } = await generateEccKeyPair();

// using a promise
generateEccKeyPair().then(({ privateKey, publicKey }) => {
  // do stuff
});
```

### generateRsaKeyPair
Generates `RSA` private and public keys.

```typescript
() => Promise<{ privateKey: string; publicKey: string}>

```
- arguments
  - none
- returns
  - Promise resolving to pem-encoded privateKey and publicKey

#### Usage
```typescript
import { generateRsaKeyPair } from 'library-crypto-typescript';

// using async/await
const { privateKey, publicKey } = await generateRsaKeyPair();

// using a promise
generateRsaKeyPair().then(({ privateKey, publicKey }) => {
  // do stuff
});
```

### sign
Signs data with a `secp256r1` private key.

```typescript
(data: Record<string, unknown>, privateKey: string) => string;

```
- arguments
  - data
    - a TypeScript object
  - privateKey
    - a pem-encoded private key
- returns
  - a signature encoded as a base58 string

#### Usage
```typescript
import { generateEccKeyPair, sign } from 'library-crypto-typescript';

const { privateKey } = await generateEccKeyPair();

const data = { some: 'data' };

const signature = sign(data, privateKey);
```

### verify
Verifies a signature with a `secp256r1` private key using the corresponding public key.

```typescript
(signature: string, data: Record<string, unknown>, publicKey: string) => boolean;
```

- arguments
  - signature
    - a cryptographic signature encoded as a base58 string
  - data
    - a TypeScript object
    - the data signed by the private key
  - publicKey
    - a pem-encoded public key
    - should correspond to the private key that signed the data
- returns
  - true if the siganture is valid, false if it is not valid

#### Usage
```typescript
import { generateEccKeyPair, sign, verify } from 'library-crypto-typescript';

const { privateKey, publicKey } = await generateEccKeyPair();

const data = { some: 'data' };

const signature = sign(data, privateKey);

const isValid = verify(signature, data, publicKey);
```

### encrypt
Encrypts data with an `RSA` public key. Returns the encrypted data encoded as a base58 string.

```typescript
(publicKey: string, data: Record<string, unknown>) => string;
```

- arguments
  - publicKey
    - a pem-encoded RSA public key
  - data
    - a TypeScript object
    - the data to encrypt
- returns
  - data encrypted with the public key and encoded as a base58 string

### Usage
```typescript
import { generateRsaKeyPair, encrypt } from 'library-crypto-typescript';

const { publicKey } = await generateRsaKeyPair();

const data = { some: 'data' };

const encryptedData = encrypt(publicKey, data);
```

### decrypt
Decrypts data encrypted with an `RSA` public key using the corresponding private key.

```typescript
(privateKey: string, encryptedData: string) => Record<string, unknown>;
```

- arguments
  - privateKey
    - a pem-encoded RSA private key
    - should correspond to the public key that encrypted the data
  - encryptedData
    - base58 encoded encrypted data
- returns
  - a TypeScript object
  - the decrypted data

#### Usage
```typescript
import { generateRsaKeyPair, encrypt, decrypt } from 'library-crypto-typescript';

const { privateKey, publicKey } = await generateRsaKeyPair();

const data = { some: 'data' };
const encryptedData = encrypt(publicKey, data);
const decryptedData = decrypt(privateKey, encryptedData);
```
