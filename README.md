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
(encoding: 'base58' | 'pem' = 'pem') => Promise<{ privateKey: string; publicKey: string}>;
```

- arguments
  - encoding
    - optional
    - the format the key should be encoded in
    - 'base58' or 'pem'
    - defaults to 'pem'
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
(encoding: 'base58' | 'pem' = 'pem') => Promise<{ privateKey: string; publicKey: string}>

```
- arguments
  - encoding
    - optional
    - the format the key should be encoded in
    - 'base58' or 'pem'
    - defaults to 'pem'
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
(data: any, privateKey: string, encoding: 'base58' | 'pem' = 'pem') => string;

```
- arguments
  - data
    - a TypeScript object
  - privateKey
    - a pem or base58-encoded private key
  - encoding
    - optional
    - the key's encoding
    - 'base58' or 'pem'
    - defaults to 'pem'
    - must match the encoding of the provided privateKey (i.e. if you provide a base58-encoded key, this must be set to 'base58')
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
(signature: string, data: any, publicKey: string, encoding: 'base58' | 'pem' = 'pem') => boolean;
```

- arguments
  - signature
    - a cryptographic signature encoded as a base58 string
  - data
    - a TypeScript object
    - the data signed by the private key
  - publicKey
    - a pem or base58-encoded public key
    - should correspond to the private key that signed the data
  - encoding
    - optional
    - the key's encoding
    - 'base58' or 'pem'
    - defaults to 'pem'
    - must match the encoding of the provided publicKey (i.e. if you provide a base58-encoded key, this must be set to 'base58')
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
Encrypts data with a single-use AES key. Returns an object contianing the encrypted data encoded as a base58 string along with information about the AES key, encrypted with an RSA public key and encoded as base58 strings

```typescript
(
  did: string,
  publicKey: string,
  data: any,
  encoding: 'base58' | 'pem' = 'pem'
) => { data: string, key: { iv: string, key: string, algorithm: string, did: string } };
```

- arguments
  - did
    - a did (with fragment) which resolves to the public key
  - publicKey
    - a pem-encoded RSA public key
  - data
    - a TypeScript object
    - the data to encrypt
  - encoding
    - optional
    - the key's encoding
    - 'base58' or 'pem'
    - defaults to 'pem'
    - must match the encoding of the provided publicKey (i.e. if you provide a base58-encoded key, this must be set to 'base58')
- returns
  - EncryptedData
    - data
      - the encrypted data, encoded as a base58 string
    - key
      - information to allow the recipient to decrypt the encrypted data
      - iv
        - the initial vector of the AES key, encrypted with the public key and encoded as a base58 string
      - key
        - the AES key, encrypted with the public key and encoded as a base58 string
      - algorithm
        - the exact algorithm used to create the AES key, encrypted with the public key and encoded as a base58 string
      - did
        - did + fragment which resolves to the public key used to encrypt `iv`, `key`, and `algorithm`

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
(
  privateKey: string,
  encryptedData: { data: string, key: { iv: string, key: string, algorithm: string, did: string } },
  encoding: 'base58' | 'pem' = 'pem'
) => any;
```

- arguments
  - privateKey
    - a pem-encoded RSA private key
    - should correspond to the public key used to encrypt the AES key contained in `encryptedData`
  - encryptedData
    - an object containing the encrypted data and information to decrypt it
  - encoding
    - optional
    - the key's encoding
    - 'base58' or 'pem'
    - defaults to 'pem'
    - must match the encoding of the provided privateKey (i.e. if you provide a base58-encoded key, this must be set to 'base58')
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
