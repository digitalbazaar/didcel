/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {
  addEvent, addVm, create, createEvent, deriveHeartbeatKeyPair,
  getPreviousEventHash, witness
} from '../../lib/index.js';
import {computeHeartbeatHash, TEST_WITNESSES} from './helpers.js';
import chai from 'chai';

const {expect} = chai;

async function runDeactivate() {
  const {heartbeatSecret, didDocument, cryptographicEventLog} = await create();

  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

  const hbKey0 = await deriveHeartbeatKeyPair(heartbeatSecret, 0);
  const hbKey1 = await deriveHeartbeatKeyPair(heartbeatSecret, 1);

  const {didDocument: updatedDoc} = await addVm({
    didDocument,
    verificationRelationship: 'authentication'
  });
  // rotate heartbeat key 0→1 in the update data
  updatedDoc.heartbeat = [await computeHeartbeatHash(heartbeatSecret, 1)];

  const updatePreviousHash =
    await getPreviousEventHash({cel: cryptographicEventLog});
  const updateEvent = await createEvent({
    type: 'update',
    data: updatedDoc,
    signingKeyPair: hbKey0,
    previousEventHash: updatePreviousHash
  });
  await addEvent({cel: cryptographicEventLog, event: updateEvent});

  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

  const deactivatePreviousHash =
    await getPreviousEventHash({cel: cryptographicEventLog});
  const deactivateEvent = await createEvent({
    type: 'deactivate',
    data: undefined,
    signingKeyPair: hbKey1,
    previousEventHash: deactivatePreviousHash
  });
  await addEvent({cel: cryptographicEventLog, event: deactivateEvent});

  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

  return {cryptographicEventLog};
}

describe('deactivate', function() {
  this.timeout(120000);

  it('should produce a 3-event hash-linked CEL with witness proofs',
    async () => {
      const {cryptographicEventLog} = await runDeactivate();

      expect(cryptographicEventLog.log).to.have.length(3);
      for(let i = 1; i < cryptographicEventLog.log.length; i++) {
        const entry = cryptographicEventLog.log[i];
        expect(entry.event).to.have.property('previousEventHash');
        expect(entry.event.previousEventHash).to.match(/^z/);
        expect(entry.proof).to.be.an('array').with.length.at.least(1);
      }
    });

  it('should have a deactivate event with no operation data', async () => {
    const {cryptographicEventLog} = await runDeactivate();

    const deactivateEntry = cryptographicEventLog.log[2];
    expect(deactivateEntry.event.operation).to.have.property(
      'type', 'deactivate');
    expect(deactivateEntry.event.operation.data).to.be.undefined;
  });
});
