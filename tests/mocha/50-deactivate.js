/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {
  addEvent, addVm, create, createCel, createEvent, witness
} from '../../lib/index.js';
import {TEST_WITNESSES} from './helpers.js';
import chai from 'chai';

const {expect} = chai;

async function runDeactivate() {
  const {keyPair, event, didDocument} = await create();
  const cryptoEventLog = createCel({event});

  await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});

  const {didDocument: updatedDoc} = await addVm({
    didDocument,
    verificationRelationship: 'authentication'
  });

  const {event: updateEvent} = await createEvent({
    type: 'update',
    data: updatedDoc,
    assertionMethod: keyPair
  });
  await addEvent({cel: cryptoEventLog, event: updateEvent});

  await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});

  const {event: deactivateEvent} = await createEvent({
    type: 'deactivate',
    data: undefined,
    assertionMethod: keyPair
  });
  await addEvent({cel: cryptoEventLog, event: deactivateEvent});

  await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});

  return {cryptoEventLog};
}

describe('deactivate', function() {
  this.timeout(120000);

  it('should produce a CEL with 3 events (create + update + deactivate)',
    async () => {
      const {cryptoEventLog} = await runDeactivate();

      expect(cryptoEventLog).to.have.property('log');
      expect(cryptoEventLog.log).to.have.length(3);
    });

  it('should have deactivate event with correct operation type', async () => {
    const {cryptoEventLog} = await runDeactivate();

    const deactivateEntry = cryptoEventLog.log[2];
    expect(deactivateEntry.event.operation).to.have.property(
      'type', 'deactivate');
    expect(deactivateEntry.event.operation.data).to.be.undefined;
  });

  it('should hash-link all events in the chain', async () => {
    const {cryptoEventLog} = await runDeactivate();

    for(let i = 1; i < cryptoEventLog.log.length; i++) {
      const entry = cryptoEventLog.log[i];
      expect(entry.event).to.have.property('previousEventHash');
      expect(entry.event.previousEventHash).to.match(/^z/);
    }
  });

  it('should have witness proofs on all events', async () => {
    const {cryptoEventLog} = await runDeactivate();

    for(const entry of cryptoEventLog.log) {
      expect(entry).to.have.property('proof');
      expect(entry.proof).to.be.an('array');
      expect(entry.proof.length).to.be.at.least(1);
    }
  });
});
