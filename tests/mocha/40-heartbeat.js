/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {
  addEvent, create, createEvent, deriveHeartbeatKeyPair, getPreviousEventHash,
  hashDidKey, witness
} from '../../lib/index.js';
import chai from 'chai';
import {TEST_WITNESSES} from './helpers.js';

const {expect} = chai;

async function runHeartbeat() {
  const {heartbeatSecret, didDocument, cryptographicEventLog} = await create();

  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

  // derive key 0 (currently in heartbeat[]) for signing this heartbeat event
  const hbKeyPair = await deriveHeartbeatKeyPair(heartbeatSecret, 0);

  // derive key 1 hash to rotate into the updated document
  const nextKeyPair = await deriveHeartbeatKeyPair(heartbeatSecret, 1);
  const nextExported =
    await nextKeyPair.export({publicKey: true, includeContext: false});
  const nextHeartbeatHash =
    await hashDidKey(`did:key:${nextExported.publicKeyMultibase}`);

  // build updated DID document: remove key 0 hash, add key 1 hash
  const updatedDoc = structuredClone(didDocument);
  updatedDoc.heartbeat = [nextHeartbeatHash];
  delete updatedDoc.proof;

  const previousEventHash =
    await getPreviousEventHash({cel: cryptographicEventLog});
  const {event: hbEvent} = await createEvent({
    type: 'update',
    data: updatedDoc,
    signer: hbKeyPair,
    previousEventHash
  });
  await addEvent({cel: cryptographicEventLog, event: hbEvent});

  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

  return {cryptographicEventLog};
}

describe('heartbeat', function() {
  this.timeout(120000);

  it('should produce a CEL with 2 events (create + heartbeat)', async () => {
    const {cryptographicEventLog} = await runHeartbeat();

    expect(cryptographicEventLog).to.have.property('log');
    expect(cryptographicEventLog.log).to.have.length(2);
  });

  it('should have heartbeat event with correct operation type', async () => {
    const {cryptographicEventLog} = await runHeartbeat();

    const heartbeatEntry = cryptographicEventLog.log[1];
    expect(heartbeatEntry.event.operation).to.have.property('type', 'update');
    expect(heartbeatEntry.event.operation.data).to.be.an('object');
  });

  it('should hash-link heartbeat event to the witnessed create event',
    async () => {
      const {cryptographicEventLog} = await runHeartbeat();

      const heartbeatEntry = cryptographicEventLog.log[1];
      expect(heartbeatEntry.event).to.have.property('previousEventHash');
      expect(heartbeatEntry.event.previousEventHash).to.match(/^z/);
    });

  it('should witness the heartbeat event', async () => {
    const {cryptographicEventLog} = await runHeartbeat();

    const heartbeatEntry = cryptographicEventLog.log[1];
    expect(heartbeatEntry).to.have.property('proof');
    expect(heartbeatEntry.proof).to.be.an('array');
    expect(heartbeatEntry.proof.length).to.be.at.least(1);
  });

  it('should sign the heartbeat event with a did:key verificationMethod',
    async () => {
      const {cryptographicEventLog} = await runHeartbeat();

      const heartbeatEntry = cryptographicEventLog.log[1];
      const vm = heartbeatEntry.event.proof?.verificationMethod;
      expect(vm).to.be.a('string').that.matches(/^did:key:/);
    });

  it('should rotate the heartbeat hash in the updated document',
    async () => {
      const {cryptographicEventLog} = await runHeartbeat();

      const createDoc =
        cryptographicEventLog.log[0].event.operation.data;
      const updateDoc =
        cryptographicEventLog.log[1].event.operation.data;

      // the hash in the updated document must differ from the original
      expect(updateDoc.heartbeat[0]).to.not.equal(createDoc.heartbeat[0]);
    });
});
