import * as helpers from '../src/helpers';

import { generateRsaKeyPair } from '../src/generateRsaKeyPair';
import { KeyPair } from '../src/types';

describe('generateRsaKeyPair', () => {
  let keypair: KeyPair;

  beforeEach(async () => {
    jest.spyOn(helpers, 'promisifiedGenerateKeyPair');
    keypair = await generateRsaKeyPair();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('generates an rsa keypair', () => {
    expect(helpers.promisifiedGenerateKeyPair).toBeCalled();
    expect((helpers.promisifiedGenerateKeyPair as jest.Mock).mock.calls[0][0]).toEqual('rsa');
  });

  it('returns the keypair', () => {
    expect(keypair.privateKey).toBeDefined();
    expect(keypair.publicKey).toBeDefined();
  });
});
