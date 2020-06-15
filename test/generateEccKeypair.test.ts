import * as helpers from '../src/helpers';

import { generateEccKeypair, Keypair } from '../src/generateEccKeypair';

describe('generateEccKeypair', () => {
  let result: Keypair;
  beforeEach(async () => {
    jest.spyOn(helpers, 'promisifiedGenerateKeyPair');
    result = await generateEccKeypair();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('generates a secp256r1 keypair', () => {
    expect(helpers.promisifiedGenerateKeyPair).toBeCalled();
    expect((helpers.promisifiedGenerateKeyPair as jest.Mock).mock.calls[0][0]).toEqual('ec');
    expect((helpers.promisifiedGenerateKeyPair as jest.Mock).mock.calls[0][1].namedCurve).toEqual('prime256v1');
  });

  it('returns the keypair', () => {
    expect(result.privateKey).toBeDefined();
    expect(result.publicKey).toBeDefined();
  });
});
