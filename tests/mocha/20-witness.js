/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {
  create, getPreviousEventHash, read, witness
} from '../../lib/index.js';
import chai from 'chai';
import {TEST_WITNESS_DIDS, TEST_WITNESSES} from './helpers.js';

const {expect} = chai;

async function runCreateAndWitness() {
  const {didDocument, cryptographicEventLog} = await create();
  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});
  return {didDocument, cryptographicEventLog};
}

function getTrustedWitnesses() {
  return TEST_WITNESS_DIDS.map(id => ({
    id,
    validFrom: '2000-01-01T00:00:00Z',
    validUntil: '2099-01-01T00:00:00Z'
  }));
}

describe('witness', function() {
  this.timeout(60000);

  it('should attach a DataIntegrityProof to the create event', async () => {
    const {didDocument, cryptographicEventLog} = await runCreateAndWitness();

    expect(didDocument.id).to.match(/^did:cel:/);
    expect(cryptographicEventLog.log).to.have.length(1);

    const createEntry = cryptographicEventLog.log[0];
    expect(createEntry.event.operation.type).to.equal('create');
    expect(createEntry).to.have.property('proof');
    expect(createEntry.proof).to.be.an('array').with.length.at.least(1);
    expect(createEntry.proof[0]).to.have.property('type', 'DataIntegrityProof');
    expect(createEntry.proof[0]).to.have.property('verificationMethod');
  });

  it('should throw when no witnesses are provided', async () => {
    const {cryptographicEventLog} = await create();

    let error;
    try {
      await witness({cel: cryptographicEventLog, witnesses: []});
    } catch(e) {
      error = e;
    }

    expect(error).to.exist;
    expect(error.message).to.include('witnesses');
  });

  it('should produce a stable previousEventHash before and after witnessing',
    async () => {
      const {cryptographicEventLog} = await create();
      const hashBefore = getPreviousEventHash({cel: cryptographicEventLog});
      await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});
      // witness proofs attach to the log entry wrapper, not the event itself —
      // the hash must be identical after witnessing
      const hashAfter = getPreviousEventHash({cel: cryptographicEventLog});

      expect(hashBefore).to.be.a('string').that.matches(/^z/);
      expect(hashAfter).to.equal(hashBefore);
    });

  it('should reject an operation proof signed with a key not in heartbeat[]',
    async () => {
      const {cryptographicEventLog} = await runCreateAndWitness();

      // replace the verificationMethod with a random did:key that was never
      // registered in heartbeat[], so the key lookup fails
      const tampered = structuredClone(cryptographicEventLog);
      tampered.log[0].event.proof.verificationMethod =
        'did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv' +
        '#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv';

      const {valid, errors} =
        await read({cel: tampered, trustedWitnesses: getTrustedWitnesses()});

      expect(valid).to.be.false;
      expect(errors.some(e =>
        e.includes('operation proof') || e.includes('heartbeat'))).to.be.true;
    });
});
