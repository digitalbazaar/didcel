/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {create, createCel} from '../../lib/index.js';
import chai from 'chai';

const {expect} = chai;

async function runCreate() {
  const {event, didDocument} = await create();
  const cryptoEventLog = createCel({event});
  return {didDocument, cryptoEventLog};
}

describe('create', function() {
  this.timeout(30000);

  it('should create a new DID document', async () => {
    const {didDocument, cryptoEventLog} = await runCreate();

    expect(didDocument.id).to.match(/^did:cel:/);
    expect(cryptoEventLog).to.have.property('log');
    expect(cryptoEventLog.log).to.have.length(1);
  });
});