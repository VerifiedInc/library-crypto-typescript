# Library-Crypto-TypeScript
A helper library for common Unum ID cryptographic functions in TypeScript.

## Installation
This library is available from [NPM](https://www.npmjs.com/package/@unumid/library-crypto), [Github packages](https://github.com/orgs/UnumID/packages?repo_name=Library-Crypto-TypeScript) or the [repository](https://github.com/UnumID/Library-Crypto-TypeScript) itself. 

## Releases
Releases of packages to the package repos, NPM and Github Packages, should be left to the Github actions CI job. The job is triggered by a tag push with a proceeding `v` followed by semver notation, i.e. v1.3.1. This will bumped the version defined in package.json and create a Github release on the semver version, 1.3.1. It will also handle publishing the package to each package repo with that same version. 

## Documentation
This readme and the auto generated [typedocs](https://docs.unum.id/Library-Crypto-TypeScript/) serve as the official documentation.

## Byte Arrays
This latest version of the crypto library only interfaces with byte arrays, specifically Uint8Array's, to remove the string encoding unknowns when dealing with cryptographic outputs from multiple platforms, (i.e. Android, Web, etc). 

### Protocol Buffers
In order to ensure a deterministic byte array cross platforms Protocol Buffers are highly recommend as the means of going to and from byte arrays. All "protobuf" objects come with built encoding and decoding helpers to assist.

## Functionality
### generateEccKeyPair
Generates `secp256r1` private and public keys.

```typescript
(encoding: 'base58' | 'pem' = 'pem') => Promise<{ id: string, privateKey: string; publicKey: string}>;
```

- arguments
  - encoding
    - optional
    - the format the key should be encoded in
    - 'base58' or 'pem'
    - defaults to 'pem'
- returns
  - Promise resolving to a KeyPair object containing the encoded public and private keys and a unique identifier for the pair

#### Usage
```typescript
import { generateEccKeyPair } from 'library-crypto-typescript';

// using async/await
const { id, privateKey, publicKey } = await generateEccKeyPair();

// using a promise
generateEccKeyPair().then(({ id, privateKey, publicKey }) => {
  // do stuff
});
```

### generateRsaKeyPair
Generates `RSA` private and public keys.

```typescript
(encoding: 'base58' | 'pem' = 'pem') => Promise<{ id: string, privateKey: string; publicKey: string}>

```
- arguments
  - encoding
    - optional
    - the format the key should be encoded in
    - 'base58' or 'pem'
    - defaults to 'pem'
- returns
  - Promise resolving to a KeyPair object containing the encoded public and private keys and a unique identifier for the pair

#### Usage
```typescript
import { generateRsaKeyPair } from 'library-crypto-typescript';

// using async/await
const { id, privateKey, publicKey } = await generateRsaKeyPair();

// using a promise
generateRsaKeyPair().then(({ id, privateKey, publicKey }) => {
  // do stuff
});
```

### signBytes
Signs bytes with a `secp256r1` private key.

```typescript
(data: Uint8Array, privateKey: string) => string;

```
- arguments
  - data
    - an Uint8Array array
  - privateKey
    - a pem or base58-encoded private key
- returns
  - a signature encoded as a base64 string

#### Usage
```typescript
import { generateEccKeyPair, signBytes } from 'library-crypto-typescript';

const { privateKey } = await generateEccKeyPair();

const data: UnsignedString = {
  data: 'Hello World'
};
const dataBytes = UnsignedString.encode(data).finish();

const signature = signBytes(dataBytes, privateKey);
```

### verifyBytes
Verifies a signature with a `secp256r1` private key using the corresponding public key.

```typescript
(signature: string, data: Uint8Array, publicKey: PublicKeyInfo) => boolean;
```

- arguments
  - signature
    - a cryptographic signature encoded as a base64 string
  - data
    - an Uint8Array array
    - signed by the private key
  - publicKey
    - a PublicKeyInfo object
    - includes a pem or base58-encoded public key
    - includes key encoding information
    - should correspond to the private key that signed the data
- returns
  - true if the siganture is valid, false if it is not valid

#### Usage
```typescript
import { generateEccKeyPair, signBytes, verifyBytes } from 'library-crypto-typescript';

const { privateKey, publicKey } = await generateEccKeyPair();

const data: UnsignedString = {
  data: 'Hello World'
};
const dataBytes = UnsignedString.encode(data).finish();

const signature = signBytes(dataBytes, privateKey);

const publicKeyInfo: PublicKeyInfo = {
  publicKey,
  encoding: 'pem'
}

const isValid = verifyBytes(signature, dataBytes, publicKeyInfo);
```

### encryptBytes
Encrypts data with a single-use AES key. Returns an object contianing the encrypted data encoded as a base64 string along with information about the AES key, encrypted with an RSA public key and encoded as base64 strings

```typescript
(
  did: string,
  publicKeyInfo: PublicKeyInfo,
  data: Uint8Array
) => { data: string, key: { iv: string, key: string, algorithm: string, did: string } };
```

- arguments
  - did
    - a did (with fragment) which resolves to the public key
  - publicKeyInfo
    - a PublicKeyInfo object
    - includes a pem or base58 encoded RSA public key
    - includes key encoding information
  - data
    - an Uint8Array array
    - the data to encrypt
- returns
  - EncryptedData
    - data
      - the encrypted data, encoded as a base64 string
    - key
      - information to allow the recipient to decrypt the encrypted data
      - iv
        - the initial vector of the AES key, encrypted with the public key and encoded as a base64 string
      - key
        - the AES key, encrypted with the public key and encoded as a base64 string
      - algorithm
        - the exact algorithm used to create the AES key, encrypted with the public key and encoded as a base64 string
      - did
        - did + fragment which resolves to the public key used to encrypt `iv`, `key`, and `algorithm`

### Usage
```typescript
import { generateRsaKeyPair, encryptBytes } from 'library-crypto-typescript';

const { publicKey } = await generateRsaKeyPair();

const publicKeyInfo: PublicKeyInfo = {
  publicKey,
  encoding: 'pem'
}

const data: UnsignedString = {
  data: 'Hello World'
};
const dataBytes = UnsignedString.encode(data).finish();

const encryptedData = encryptBytes(did, dataBytes, publicKeyInfo);
```

### decryptBytes
Decrypts data encrypted with an `RSA` public key using the corresponding private key.

```typescript
(
  privateKey: string,
  encryptedData: { data: string, key: { iv: string, key: string, algorithm: string, did: string } }
) => any;
```

- arguments
  - privateKey
    - a pem or base58 RSA private key
    - should correspond to the public key used to encrypt the AES key contained in `encryptedData`
  - encryptedData
    - an object containing the encrypted data and information to decrypt it
- returns
  - the decrypted data in the form a byte array

#### Usage
```typescript
import { generateRsaKeyPair, encryptBytes, decryptBytes } from 'library-crypto-typescript';

const { privateKey, publicKey } = await generateRsaKeyPair();

const publicKeyInfo: PublicKeyInfo = {
  publicKey,
  encoding: 'pem'
}

const data: UnsignedString = {
  data: 'Hello World'
};
const dataBytes = UnsignedString.encode(data).finish();
const encryptedData = encryptBytes(did, publicKeyInfo, data);
const decryptedData = decryptBytes(privateKey, encryptedData);
```
