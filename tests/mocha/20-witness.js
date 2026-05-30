/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {TEST_WITNESSES} from './helpers.js';
import {create, createCel, witness} from '../../lib/index.js';
import chai from 'chai';

const {expect} = chai;

async function runCreateAndWitness() {
  const {event, didDocument} = await create();
  const cryptoEventLog = createCel({event});
  await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});
  return {didDocument, cryptoEventLog};
}

describe('witness', function() {
  this.timeout(60000);

  it('should create and witness a DID', async () => {
    const {didDocument, cryptoEventLog} = await runCreateAndWitness();

    expect(didDocument.id).to.match(/^did:cel:/);
    expect(cryptoEventLog.log).to.have.length(1);
  });

  it('should produce a CEL with a witness proof on the create event',
    async () => {
      const {cryptoEventLog} = await runCreateAndWitness();

      const createEntry = cryptoEventLog.log[0];
      expect(createEntry).to.have.property('proof');
      expect(createEntry.proof).to.be.an('array');
      expect(createEntry.proof.length).to.be.at.least(1);

      const proof = createEntry.proof[0];
      expect(proof).to.have.property('type', 'DataIntegrityProof');
      expect(proof).to.have.property('verificationMethod');
    });

  it('should have witness proof with a real verificationMethod', async () => {
    const {cryptoEventLog} = await runCreateAndWitness();

    const proof = cryptoEventLog.log[0].proof[0];
    expect(proof.verificationMethod).to.match(/^did:key:/);
  });
});