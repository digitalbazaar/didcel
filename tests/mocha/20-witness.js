/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {
  LOGS_DIR, SECRETS_DIR, TEST_PASSWORD, TEST_WITNESSES,
  listCelFiles, listSecretFiles
} from './helpers.js';
import {create} from '../../lib/didcel.js';
import {create as createCel, witness} from '../../lib/cel.js';
import {saveSecrets} from '../../lib/secrets.js';
import chai from 'chai';
import {join} from 'node:path';
import {readFileSync, writeFileSync} from 'node:fs';

const {expect} = chai;

async function runCreateAndWitness() {
  const {keyPair, recoveryKeyPair, event, didDocument} = await create();
  const cryptoEventLog = createCel({event});
  await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});
  const didIdentifier = didDocument.id.replace('did:cel:', '');
  const celPath = join(LOGS_DIR, `${didIdentifier}.cel`);
  writeFileSync(celPath, JSON.stringify(cryptoEventLog, null, 2));
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
  return {didDocument, cryptoEventLog, celPath};
}

describe('witness', function() {
  this.timeout(60000);

  it('should create, witness, and save a DID', async () => {
    const beforeCel = listCelFiles().length;
    const beforeSecrets = listSecretFiles().length;

    const {didDocument} = await runCreateAndWitness();

    expect(didDocument.id).to.match(/^did:cel:/);
    expect(listCelFiles()).to.have.length(beforeCel + 1);
    expect(listSecretFiles()).to.have.length(beforeSecrets + 1);
  });

  it('should produce a CEL with a witness proof on the create event',
    async () => {
      const {celPath} = await runCreateAndWitness();

      const celContent = JSON.parse(readFileSync(celPath, 'utf8'));

      expect(celContent).to.have.property('log');
      expect(celContent.log).to.have.length(1);

      const createEntry = celContent.log[0];
      expect(createEntry).to.have.property('proof');
      expect(createEntry.proof).to.be.an('array');
      expect(createEntry.proof.length).to.be.at.least(1);

      const proof = createEntry.proof[0];
      expect(proof).to.have.property('type', 'DataIntegrityProof');
      expect(proof).to.have.property('verificationMethod');
    });

  it('should have witness proof with a real verificationMethod', async () => {
    const {celPath} = await runCreateAndWitness();

    const celContent = JSON.parse(readFileSync(celPath, 'utf8'));

    const proof = celContent.log[0].proof[0];
    // verificationMethod should reference a real did:key (not a placeholder)
    expect(proof.verificationMethod).to.match(/^did:key:/);
  });
});