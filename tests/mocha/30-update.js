/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {
  addEvent, addVm, create, createCel, createEvent, getPreviousEventHash,
  witness
} from '../../lib/index.js';
import {TEST_WITNESSES} from './helpers.js';
import chai from 'chai';

const {expect} = chai;

async function runUpdate() {
  const {keyPair, event, didDocument} = await create();
  const cryptoEventLog = createCel({event});

  await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});

  const {didDocument: updatedDoc} = await addVm({
    didDocument,
    verificationRelationship: 'authentication'
  });

  const previousEventHash = await getPreviousEventHash({cel: cryptoEventLog});
  const {event: updateEvent} = await createEvent({
    type: 'update',
    data: updatedDoc,
    assertionMethod: keyPair,
    previousEventHash
  });
  await addEvent({cel: cryptoEventLog, event: updateEvent});

  await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});

  return {cryptoEventLog};
}

describe('update', function() {
  this.timeout(120000);

  it('should produce a CEL with 2 events (create + update)', async () => {
    const {cryptoEventLog} = await runUpdate();

    expect(cryptoEventLog).to.have.property('log');
    expect(cryptoEventLog.log).to.have.length(2);
  });

  it('should hashlink events via previousEventHash', async () => {
    const {cryptoEventLog} = await runUpdate();

    const updateEntry = cryptoEventLog.log[1];
    expect(updateEntry.event).to.have.property('previousEventHash');
    expect(updateEntry.event.previousEventHash).to.be.a('string');
    expect(updateEntry.event.previousEventHash).to.match(/^z/);
  });

  it('should include the new authentication key in the update event',
    async () => {
      const {cryptoEventLog} = await runUpdate();

      const updateEntry = cryptoEventLog.log[1];
      expect(updateEntry.event.operation.type).to.equal('update');
      const didDoc = updateEntry.event.operation.data;
      expect(didDoc).to.have.property('authentication');
      expect(didDoc.authentication).to.be.an('array');
      expect(didDoc.authentication.length).to.be.at.least(1);
    });

  it('should have witness proofs on both events', async () => {
    const {cryptoEventLog} = await runUpdate();

    for(const entry of cryptoEventLog.log) {
      expect(entry).to.have.property('proof');
      expect(entry.proof).to.be.an('array');
      expect(entry.proof.length).to.be.at.least(1);
    }
  });
});
