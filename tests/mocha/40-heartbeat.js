/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {
  LOGS_DIR, SECRETS_DIR, TEST_PASSWORD, TEST_WITNESSES,
  listCelFiles
} from './helpers.js';
import {create, createEvent} from '../../lib/didcel.js';
import {addEvent, create as createCel, witness} from '../../lib/cel.js';
import {saveSecrets} from '../../lib/secrets.js';
import chai from 'chai';
import {join} from 'node:path';
import {readFileSync, writeFileSync} from 'node:fs';

const {expect} = chai;

async function runHeartbeat() {
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

  // sign and append heartbeat event
  const {event: hbEvent} = await createEvent({
    type: 'heartbeat',
    data: undefined,
    assertionMethod: secretKeys.assertionMethod[0]
  });
  await addEvent({cel: cryptoEventLog, event: hbEvent});

  // witness heartbeat event
  await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});

  // save
  const didIdentifier = didDocument.id.replace('did:cel:', '');
  const celPath = join(LOGS_DIR, `${didIdentifier}.cel`);
  writeFileSync(celPath, JSON.stringify(cryptoEventLog, null, 2));
  await saveSecrets(
    {didIdentifier, secretKeys, password: TEST_PASSWORD, secretsDir: SECRETS_DIR});

  return {celPath};
}

describe('heartbeat', function() {
  this.timeout(120000);

  it('should create, witness, heartbeat, witness, and save', async () => {
    const before = listCelFiles().length;

    await runHeartbeat();

    expect(listCelFiles()).to.have.length(before + 1);
  });

  it('should produce a CEL with 2 events (create + heartbeat)', async () => {
    const {celPath} = await runHeartbeat();

    const celContent = JSON.parse(readFileSync(celPath, 'utf8'));

    expect(celContent).to.have.property('log');
    expect(celContent.log).to.have.length(2);
  });

  it('should have heartbeat event with correct operation type', async () => {
    const {celPath} = await runHeartbeat();

    const celContent = JSON.parse(readFileSync(celPath, 'utf8'));

    const heartbeatEntry = celContent.log[1];
    expect(heartbeatEntry.event.operation).to.have.property(
      'type', 'heartbeat');
    expect(heartbeatEntry.event.operation.data).to.be.undefined;
  });

  it('should hash-link heartbeat event to the witnessed create event',
    async () => {
      const {celPath} = await runHeartbeat();

      const celContent = JSON.parse(readFileSync(celPath, 'utf8'));

      const heartbeatEntry = celContent.log[1];
      expect(heartbeatEntry.event).to.have.property('previousEventHash');
      expect(heartbeatEntry.event.previousEventHash).to.match(/^z/);
    });

  it('should witness the heartbeat event', async () => {
    const {celPath} = await runHeartbeat();

    const celContent = JSON.parse(readFileSync(celPath, 'utf8'));

    const heartbeatEntry = celContent.log[1];
    expect(heartbeatEntry).to.have.property('proof');
    expect(heartbeatEntry.proof).to.be.an('array');
    expect(heartbeatEntry.proof.length).to.be.at.least(1);
  });
});