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

async function runDeactivate() {
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

  // sign and append deactivate event
  const {event: deactivateEvent} = await createEvent({
    type: 'deactivate',
    data: undefined,
    assertionMethod: secretKeys.assertionMethod[0]
  });
  await addEvent({cel: cryptoEventLog, event: deactivateEvent});

  // witness deactivate event
  await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});

  // save
  const didIdentifier = didDocument.id.replace('did:cel:', '');
  const celPath = join(LOGS_DIR, `${didIdentifier}.cel`);
  writeFileSync(celPath, JSON.stringify(cryptoEventLog, null, 2));
  await saveSecrets(
    {didIdentifier, secretKeys, password: TEST_PASSWORD, secretsDir: SECRETS_DIR});

  return {celPath};
}

describe('deactivate', function() {
  this.timeout(120000);

  it('should create, witness, add key, update, witness, deactivate, witness, ' +
    'and save', async () => {
    const before = listCelFiles().length;

    await runDeactivate();

    expect(listCelFiles()).to.have.length(before + 1);
  });

  it('should produce a CEL with 3 events (create + update + deactivate)',
    async () => {
      const {celPath} = await runDeactivate();

      const celContent = JSON.parse(readFileSync(celPath, 'utf8'));

      expect(celContent).to.have.property('log');
      expect(celContent.log).to.have.length(3);
    });

  it('should have deactivate event with correct operation type', async () => {
    const {celPath} = await runDeactivate();

    const celContent = JSON.parse(readFileSync(celPath, 'utf8'));

    const deactivateEntry = celContent.log[2];
    expect(deactivateEntry.event.operation).to.have.property(
      'type', 'deactivate');
    expect(deactivateEntry.event.operation.data).to.be.undefined;
  });

  it('should hash-link all events in the chain', async () => {
    const {celPath} = await runDeactivate();

    const celContent = JSON.parse(readFileSync(celPath, 'utf8'));

    for(let i = 1; i < celContent.log.length; i++) {
      const entry = celContent.log[i];
      expect(entry.event).to.have.property('previousEventHash');
      expect(entry.event.previousEventHash).to.match(/^z/);
    }
  });

  it('should have witness proofs on all events', async () => {
    const {celPath} = await runDeactivate();

    const celContent = JSON.parse(readFileSync(celPath, 'utf8'));

    for(const entry of celContent.log) {
      expect(entry).to.have.property('proof');
      expect(entry.proof).to.be.an('array');
      expect(entry.proof.length).to.be.at.least(1);
    }
  });
});