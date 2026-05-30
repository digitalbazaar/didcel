/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {
  LOGS_DIR, SECRETS_DIR, TEST_PASSWORD, TEST_WITNESSES,
  listCelFiles
} from './helpers.js';
import {addVm, create, createEvent} from '../../lib/didcel.js';
import {addEvent, create as createCel, witness} from '../../lib/cel.js';
import {saveSecrets} from '../../lib/secrets.js';
import chai from 'chai';
import {join} from 'node:path';
import {readFileSync, writeFileSync} from 'node:fs';

const {expect} = chai;

async function runUpdate() {
  // create DID
  const {keyPair, recoveryKeyPair, event, didDocument} = await create();
  const cryptoEventLog = createCel({event});
  const secretKeys = {
    authentication: [],
    assertionMethod: [keyPair],
    capabilityInvocation: [],
    capabilityDelegation: [],
    keyAgreement: [],
    recovery: [recoveryKeyPair]
  };

  // witness create event
  await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});

  // add authentication key
  const {keyPair: authKeyPair, didDocument: updatedDoc} = await addVm({
    didDocument,
    verificationRelationship: 'authentication'
  });
  secretKeys.authentication.push(authKeyPair);

  // sign and append update event
  const {event: updateEvent} = await createEvent({
    type: 'update',
    data: updatedDoc,
    assertionMethod: secretKeys.assertionMethod[0]
  });
  await addEvent({cel: cryptoEventLog, event: updateEvent});

  // witness update event
  await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});

  // save
  const didIdentifier = didDocument.id.replace('did:cel:', '');
  const celPath = join(LOGS_DIR, `${didIdentifier}.cel`);
  writeFileSync(celPath, JSON.stringify(cryptoEventLog, null, 2));
  await saveSecrets(
    {didIdentifier, secretKeys, password: TEST_PASSWORD, secretsDir: SECRETS_DIR});

  return {celPath};
}

describe('update', function() {
  this.timeout(120000);

  it('should create, witness, add auth key, update, witness, and save',
    async () => {
      const before = listCelFiles().length;

      await runUpdate();

      expect(listCelFiles()).to.have.length(before + 1);
    });

  it('should produce a CEL with 2 events (create + update)', async () => {
    const {celPath} = await runUpdate();

    const celContent = JSON.parse(readFileSync(celPath, 'utf8'));

    expect(celContent).to.have.property('log');
    expect(celContent.log).to.have.length(2);
  });

  it('should hashlink events via previousEventHash', async () => {
    const {celPath} = await runUpdate();

    const celContent = JSON.parse(readFileSync(celPath, 'utf8'));

    const updateEntry = celContent.log[1];
    expect(updateEntry.event).to.have.property('previousEventHash');
    expect(updateEntry.event.previousEventHash).to.be.a('string');
    expect(updateEntry.event.previousEventHash).to.match(/^z/);
  });

  it('should include the new authentication key in the update event',
    async () => {
      const {celPath} = await runUpdate();

      const celContent = JSON.parse(readFileSync(celPath, 'utf8'));

      const updateEntry = celContent.log[1];
      const didDoc = updateEntry.event.operation.data;
      expect(didDoc).to.have.property('authentication');
      expect(didDoc.authentication).to.be.an('array');
      expect(didDoc.authentication.length).to.be.at.least(1);
    });

  it('should witness proofs on both events', async () => {
    const {celPath} = await runUpdate();

    const celContent = JSON.parse(readFileSync(celPath, 'utf8'));

    for(const entry of celContent.log) {
      expect(entry).to.have.property('proof');
      expect(entry.proof).to.be.an('array');
      expect(entry.proof.length).to.be.at.least(1);
    }
  });
});