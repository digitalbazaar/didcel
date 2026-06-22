/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import chai from 'chai';
import {create} from '../../lib/index.js';

const {expect} = chai;

describe('create', function() {
  this.timeout(30000);

  it('should create a well-formed DID document', async () => {
    const {didDocument, cryptographicEventLog} = await create();

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

    // heartbeat: one base58btc-encoded SHA3-256 multihash of a did:key URI
    expect(didDocument.heartbeat).to.be.an('array').with.length(1);
    const heartbeatHash = didDocument.heartbeat[0];
    expect(heartbeatHash).to.be.a('string').that.matches(/^z/);

    // service: must be an array of service objects (DID Core conformant)
    expect(didDocument.service).to.be.an('array').with.length.at.least(1);
    expect(didDocument.service[0]).to.have.property(
      'type', 'CelStorageService');
    expect(didDocument.service[0].serviceEndpoint).to.be.an('array')
      .with.length.at.least(1);

    // CEL create event
    const createEntry = cryptographicEventLog.log[0];
    expect(createEntry.event.operation.type).to.equal('create');
    expect(createEntry.event.operation.data.id).to.equal(didDocument.id);
    expect(createEntry.event.proof).to.have.property(
      'type', 'DataIntegrityProof');
  });
});
