/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {
  addEvent, create, createEvent, deriveHeartbeatKeyPair, getPreviousEventHash,
  witness
} from '../../lib/index.js';
import {computeHeartbeatHash, TEST_WITNESSES} from './helpers.js';
import chai from 'chai';

const {expect} = chai;

async function runHeartbeat() {
  const {heartbeatSecret, cryptographicEventLog} = await create();

  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

  // derive key 0 (currently in heartbeat[]) for signing this heartbeat event
  const hbKeyPair = await deriveHeartbeatKeyPair(heartbeatSecret, 0);

  const previousEventHash =
    await getPreviousEventHash({cel: cryptographicEventLog});
  const hbEvent = await createEvent({
    type: 'heartbeat',
    data: {heartbeat: [await computeHeartbeatHash(heartbeatSecret, 1)]},
    signingKeyPair: hbKeyPair,
    previousEventHash
  });
  await addEvent({cel: cryptographicEventLog, event: hbEvent});

  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

  return {cryptographicEventLog};
}

describe('heartbeat', function() {
  this.timeout(120000);

  it('should produce a 2-event hash-linked CEL signed with a did:key',
    async () => {
      const {cryptographicEventLog} = await runHeartbeat();

      expect(cryptographicEventLog.log).to.have.length(2);
      const heartbeatEntry = cryptographicEventLog.log[1];
      expect(heartbeatEntry.event).to.have.property('previousEventHash');
      expect(heartbeatEntry.event.previousEventHash).to.match(/^z/);
      const vm = heartbeatEntry.event.proof?.verificationMethod;
      expect(vm).to.be.a('string').that.matches(/^did:key:/);
    });

  it('should carry a rotated heartbeat hash and a witness proof',
    async () => {
      const {cryptographicEventLog} = await runHeartbeat();

      const heartbeatEntry = cryptographicEventLog.log[1];
      expect(heartbeatEntry.event.operation.type).to.equal('heartbeat');
      expect(heartbeatEntry).to.have.property('proof');
      expect(heartbeatEntry.proof).to.be.an('array').with.length.at.least(1);

      const createDoc = cryptographicEventLog.log[0].event.operation.data;
      const hbDoc = heartbeatEntry.event.operation.data;
      expect(hbDoc.heartbeat[0]).to.not.equal(createDoc.heartbeat[0]);
    });
});
