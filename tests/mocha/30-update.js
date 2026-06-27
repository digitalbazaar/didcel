/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {
  addEvent, addVm, create, createEvent, deriveHeartbeatKeyPair,
  getPreviousEventHash, sha3256Multibase, witness
} from '../../lib/index.js';
import chai from 'chai';
import {TEST_WITNESSES} from './helpers.js';

const {expect} = chai;

async function nextHeartbeatHash(heartbeatSecret, index) {
  const kp = await deriveHeartbeatKeyPair(heartbeatSecret, index);
  const exported = await kp.export({publicKey: true, includeContext: false});
  return sha3256Multibase(`did:key:${exported.publicKeyMultibase}`);
}

async function runUpdate() {
  const {heartbeatSecret, didDocument, cryptographicEventLog} = await create();

  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

  const hbKey0 = await deriveHeartbeatKeyPair(heartbeatSecret, 0);

  const {didDocument: updatedDoc} = await addVm({
    didDocument,
    verificationRelationship: 'authentication'
  });
  // rotation is required for every non-deactivate event
  updatedDoc.heartbeat = [await nextHeartbeatHash(heartbeatSecret, 1)];

  const previousEventHash =
    await getPreviousEventHash({cel: cryptographicEventLog});
  const {event: updateEvent} = await createEvent({
    type: 'update',
    data: updatedDoc,
    signingKeyPair: hbKey0,
    previousEventHash
  });
  await addEvent({cel: cryptographicEventLog, event: updateEvent});

  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

  return {cryptographicEventLog};
}

describe('update', function() {
  this.timeout(120000);

  it('should produce a CEL with 2 events (create + update)', async () => {
    const {cryptographicEventLog} = await runUpdate();

    expect(cryptographicEventLog).to.have.property('log');
    expect(cryptographicEventLog.log).to.have.length(2);
  });

  it('should hashlink events via previousEventHash', async () => {
    const {cryptographicEventLog} = await runUpdate();

    const updateEntry = cryptographicEventLog.log[1];
    expect(updateEntry.event).to.have.property('previousEventHash');
    expect(updateEntry.event.previousEventHash).to.be.a('string');
    expect(updateEntry.event.previousEventHash).to.match(/^z/);
  });

  it('should include the new authentication key in the update event',
    async () => {
      const {cryptographicEventLog} = await runUpdate();

      const updateEntry = cryptographicEventLog.log[1];
      expect(updateEntry.event.operation.type).to.equal('update');
      const didDoc = updateEntry.event.operation.data;
      expect(didDoc).to.have.property('authentication');
      expect(didDoc.authentication).to.be.an('array');
      expect(didDoc.authentication.length).to.be.at.least(1);
    });

  it('should have witness proofs on both events', async () => {
    const {cryptographicEventLog} = await runUpdate();

    for(const entry of cryptographicEventLog.log) {
      expect(entry).to.have.property('proof');
      expect(entry.proof).to.be.an('array');
      expect(entry.proof.length).to.be.at.least(1);
    }
  });

  it('should throw MALFORMED_CEL_ERROR when adding an event to an empty log',
    async () => {
      const {heartbeatSecret, didDocument} = await create();
      const hbKey0 = await deriveHeartbeatKeyPair(heartbeatSecret, 0);
      const updatedDoc = structuredClone(didDocument);
      updatedDoc.heartbeat = [await nextHeartbeatHash(heartbeatSecret, 1)];
      const {event: updateEvent} = await createEvent({
        type: 'update', data: updatedDoc, signingKeyPair: hbKey0,
        previousEventHash: undefined
      });

      let error;
      try {
        await addEvent({cel: {log: []}, event: updateEvent});
      } catch(e) {
        error = e;
      }

      expect(error).to.exist;
      expect(error.name).to.equal('MALFORMED_CEL_ERROR');
    });
});
