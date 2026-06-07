/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {create, witness} from '../../lib/index.js';
import {TEST_WITNESSES} from './helpers.js';
import chai from 'chai';

const {expect} = chai;

async function runCreateAndWitness() {
  const {didDocument, cryptographicEventLog} = await create();
  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});
  return {didDocument, cryptographicEventLog};
}

describe('witness', function() {
  this.timeout(60000);

  it('should create and witness a DID', async () => {
    const {didDocument, cryptographicEventLog} = await runCreateAndWitness();

    expect(didDocument.id).to.match(/^did:cel:/);
    expect(cryptographicEventLog.log).to.have.length(1);
  });

  it('should produce a CEL with a witness proof on the create event',
    async () => {
      const {cryptographicEventLog} = await runCreateAndWitness();

      const createEntry = cryptographicEventLog.log[0];
      expect(createEntry.event.operation.type).to.equal('create');
      expect(createEntry).to.have.property('proof');
      expect(createEntry.proof).to.be.an('array');
      expect(createEntry.proof.length).to.be.at.least(1);

      const proof = createEntry.proof[0];
      expect(proof).to.have.property('type', 'DataIntegrityProof');
      expect(proof).to.have.property('verificationMethod');
    });
});
