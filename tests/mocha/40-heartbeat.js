/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {
  addEvent, create, createCel, createEvent, witness
} from '../../lib/index.js';
import {TEST_WITNESSES} from './helpers.js';
import chai from 'chai';

const {expect} = chai;

async function runHeartbeat() {
  const {keyPair, event} = await create();
  const cryptoEventLog = createCel({event});

  await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});

  const {event: hbEvent} = await createEvent({
    type: 'heartbeat',
    data: undefined,
    assertionMethod: keyPair
  });
  await addEvent({cel: cryptoEventLog, event: hbEvent});

  await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});

  return {cryptoEventLog};
}

describe('heartbeat', function() {
  this.timeout(120000);

  it('should produce a CEL with 2 events (create + heartbeat)', async () => {
    const {cryptoEventLog} = await runHeartbeat();

    expect(cryptoEventLog).to.have.property('log');
    expect(cryptoEventLog.log).to.have.length(2);
  });

  it('should have heartbeat event with correct operation type', async () => {
    const {cryptoEventLog} = await runHeartbeat();

    const heartbeatEntry = cryptoEventLog.log[1];
    expect(heartbeatEntry.event.operation).to.have.property(
      'type', 'heartbeat');
    expect(heartbeatEntry.event.operation.data).to.be.undefined;
  });

  it('should hash-link heartbeat event to the witnessed create event',
    async () => {
      const {cryptoEventLog} = await runHeartbeat();

      const heartbeatEntry = cryptoEventLog.log[1];
      expect(heartbeatEntry.event).to.have.property('previousEventHash');
      expect(heartbeatEntry.event.previousEventHash).to.match(/^z/);
    });

  it('should witness the heartbeat event', async () => {
    const {cryptoEventLog} = await runHeartbeat();

    const heartbeatEntry = cryptoEventLog.log[1];
    expect(heartbeatEntry).to.have.property('proof');
    expect(heartbeatEntry.proof).to.be.an('array');
    expect(heartbeatEntry.proof.length).to.be.at.least(1);
  });
});
