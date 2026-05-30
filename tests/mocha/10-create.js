/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {
  LOGS_DIR, SECRETS_DIR, TEST_PASSWORD,
  listCelFiles, listSecretFiles
} from './helpers.js';
import {create} from '../../lib/didcel.js';
import {create as createCel} from '../../lib/cel.js';
import {saveSecrets} from '../../lib/secrets.js';
import chai from 'chai';
import {join} from 'node:path';
import {writeFileSync} from 'node:fs';

const {expect} = chai;

async function runCreate() {
  const {keyPair, recoveryKeyPair, event, didDocument} = await create();
  const cryptoEventLog = createCel({event});
  const didIdentifier = didDocument.id.replace('did:cel:', '');
  writeFileSync(
    join(LOGS_DIR, `${didIdentifier}.cel`),
    JSON.stringify(cryptoEventLog, null, 2));
  const secretKeys = {
    authentication: [],
    assertionMethod: [keyPair],
    capabilityInvocation: [],
    capabilityDelegation: [],
    keyAgreement: [],
    recovery: [recoveryKeyPair]
  };
  await saveSecrets(
    {didIdentifier, secretKeys, password: TEST_PASSWORD, secretsDir: SECRETS_DIR});
  return {didDocument, cryptoEventLog};
}

describe('create', function() {
  this.timeout(30000);

  it('should create a new DID document and save', async () => {
    const beforeCel = listCelFiles().length;
    const beforeSecrets = listSecretFiles().length;

    const {didDocument} = await runCreate();

    expect(didDocument.id).to.match(/^did:cel:/);
    expect(listCelFiles()).to.have.length(beforeCel + 1);
    expect(listSecretFiles()).to.have.length(beforeSecrets + 1);
  });

  it('should create multiple DIDs independently', async () => {
    const before = listCelFiles().length;

    await runCreate();
    await runCreate();

    expect(listCelFiles()).to.have.length(before + 2);
  });
});