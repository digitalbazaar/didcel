/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {
  addEvent, addVm, create, createEvent, getPreviousEventHash, witness
} from '../../lib/index.js';
import {TEST_WITNESSES} from './helpers.js';
import chai from 'chai';

const {expect} = chai;

async function runDeactivate() {
  const {keyPair, didDocument, cryptographicEventLog} = await create();

  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

  const {didDocument: updatedDoc} = await addVm({
    didDocument,
    verificationRelationship: 'authentication'
  });

  const updatePreviousHash =
    await getPreviousEventHash({cel: cryptographicEventLog});
  const {event: updateEvent} = await createEvent({
    type: 'update',
    data: updatedDoc,
    assertionMethod: keyPair,
    previousEventHash: updatePreviousHash
  });
  await addEvent({cel: cryptographicEventLog, event: updateEvent});

  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

  const deactivatePreviousHash =
    await getPreviousEventHash({cel: cryptographicEventLog});
  const {event: deactivateEvent} = await createEvent({
    type: 'deactivate',
    data: undefined,
    assertionMethod: keyPair,
    previousEventHash: deactivatePreviousHash
  });
  await addEvent({cel: cryptographicEventLog, event: deactivateEvent});

  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

  return {cryptographicEventLog};
}

describe('deactivate', function() {
  this.timeout(120000);

  it('should produce a CEL with 3 events (create + update + deactivate)',
    async () => {
      const {cryptographicEventLog} = await runDeactivate();

      expect(cryptographicEventLog).to.have.property('log');
      expect(cryptographicEventLog.log).to.have.length(3);
    });

  it('should have deactivate event with correct operation type', async () => {
    const {cryptographicEventLog} = await runDeactivate();

    const deactivateEntry = cryptographicEventLog.log[2];
    expect(deactivateEntry.event.operation).to.have.property(
      'type', 'deactivate');
    expect(deactivateEntry.event.operation.data).to.be.undefined;
  });

  it('should hash-link all events in the chain', async () => {
    const {cryptographicEventLog} = await runDeactivate();

    for(let i = 1; i < cryptographicEventLog.log.length; i++) {
      const entry = cryptographicEventLog.log[i];
      expect(entry.event).to.have.property('previousEventHash');
      expect(entry.event.previousEventHash).to.match(/^z/);
    }
  });

  it('should have witness proofs on all events', async () => {
    const {cryptographicEventLog} = await runDeactivate();

    for(const entry of cryptographicEventLog.log) {
      expect(entry).to.have.property('proof');
      expect(entry.proof).to.be.an('array');
      expect(entry.proof.length).to.be.at.least(1);
    }
  });
});
