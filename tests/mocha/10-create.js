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

  it('should create a well-formed DID document', async () => {
    const {didDocument, cryptoEventLog} = await runCreate();

    // identifier
    expect(didDocument.id).to.match(/^did:cel:z/);

    // JSON-LD contexts
    expect(didDocument['@context']).to.be.an('array');
    expect(didDocument['@context']).to.include('https://www.w3.org/ns/did/v1.1');
    expect(didDocument['@context']).to.include('https://w3id.org/didcel/v1');

    // heartbeat frequency
    expect(didDocument.heartbeatFrequency).to.be.a('string').that.is.not.empty;

    // assertionMethod: one embedded key with required fields
    expect(didDocument.assertionMethod).to.be.an('array').with.length(1);
    const assertionKey = didDocument.assertionMethod[0];
    expect(assertionKey.type).to.equal('Multikey');
    expect(assertionKey.controller).to.equal(didDocument.id);
    expect(assertionKey.publicKeyMultibase).to.be.a('string').that.is.not.empty;

    // recovery: one embedded key
    expect(didDocument.recovery).to.be.an('array').with.length(1);
    const recoveryKey = didDocument.recovery[0];
    expect(recoveryKey.type).to.equal('Multikey');
    expect(recoveryKey.controller).to.equal(didDocument.id);
    expect(assertionKey.publicKeyMultibase).to.be.a('string').that.is.not.empty;

    // service
    expect(didDocument.service).to.have.property('type', 'CelStorageService');
    expect(didDocument.service.serviceEndpoint).to.be.an('array')
      .with.length.at.least(1);

    // CEL create event
    const createEntry = cryptoEventLog.log[0];
    expect(createEntry.event.operation.type).to.equal('create');
    expect(createEntry.event.operation.data.id).to.equal(didDocument.id);
    expect(createEntry.event.proof).to.have.property(
      'type', 'DataIntegrityProof');
  });
});
