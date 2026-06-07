/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {
  addEvent, create, createEvent, getPreviousEventHash, witness
} from '../../lib/index.js';
import chai from 'chai';
import {TEST_WITNESSES} from './helpers.js';

const {expect} = chai;

async function runHeartbeat() {
  const {keyPair, cryptographicEventLog} = await create();

  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

  const previousEventHash =
    await getPreviousEventHash({cel: cryptographicEventLog});
  const {event: hbEvent} = await createEvent({
    type: 'heartbeat',
    data: undefined,
    assertionMethod: keyPair,
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
    expect(heartbeatEntry.event.operation).to.have.property(
      'type', 'heartbeat');
    expect(heartbeatEntry.event.operation.data).to.be.undefined;
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
});
