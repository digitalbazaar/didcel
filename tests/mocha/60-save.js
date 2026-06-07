/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {
  addEvent, create, createEvent, getPreviousEventHash, loadFromFile,
  loadSecrets, saveSecrets, setHeartbeatFrequency, witness
} from '../../lib/index.js';
import {mkdirSync, mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {TEST_PASSWORD, TEST_WITNESS_DIDS, TEST_WITNESSES} from './helpers.js';
import chai from 'chai';
import {join} from 'node:path';
import {tmpdir} from 'node:os';

const {expect} = chai;

describe('save', function() {
  this.timeout(120000);

  let tmpDir;
  let logsDir;
  let secretsDir;

  before(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'didcel-test-'));
    logsDir = join(tmpDir, 'logs');
    secretsDir = join(tmpDir, 'secrets');
    mkdirSync(logsDir, {recursive: true});
  });

  after(() => {
    rmSync(tmpDir, {recursive: true, force: true});
  });

  describe('saveSecrets / loadSecrets', function() {
    it('should save and load secrets with the correct key pairs', async () => {
      const {keyPair, didDocument} = await create();
      const didIdentifier = didDocument.id.replace('did:cel:', '');
      const secretKeys = {
        authentication: [],
        assertionMethod: [keyPair],
        capabilityInvocation: [],
        capabilityDelegation: [],
        keyAgreement: []
      };

      await saveSecrets(
        {didIdentifier, secretKeys, password: TEST_PASSWORD, secretsDir});

      const loaded = await loadSecrets(
        {didIdentifier, password: TEST_PASSWORD, secretsDir});

      expect(loaded.assertionMethod).to.have.length(1);
      const exportedOriginal =
        await keyPair.export({publicKey: true, includeContext: false});
      const exportedLoaded =
        await loaded.assertionMethod[0].export(
          {publicKey: true, includeContext: false});
      expect(exportedLoaded.publicKeyMultibase)
        .to.equal(exportedOriginal.publicKeyMultibase);
    });

    it('should save secrets across multiple relationships', async () => {
      const {keyPair, didDocument} = await create();
      const {keyPair: authKeyPair} = await create();
      const didIdentifier = didDocument.id.replace('did:cel:', '');
      const secretKeys = {
        authentication: [authKeyPair],
        assertionMethod: [keyPair],
        capabilityInvocation: [],
        capabilityDelegation: [],
        keyAgreement: []
      };

      await saveSecrets(
        {didIdentifier, secretKeys, password: TEST_PASSWORD, secretsDir});

      const loaded = await loadSecrets(
        {didIdentifier, password: TEST_PASSWORD, secretsDir});

      expect(loaded.assertionMethod).to.have.length(1);
      expect(loaded.authentication).to.have.length(1);
    });

    it('should fail to load secrets with wrong password', async () => {
      const {keyPair, didDocument} = await create();
      const didIdentifier = didDocument.id.replace('did:cel:', '');
      const secretKeys = {
        authentication: [],
        assertionMethod: [keyPair],
        capabilityInvocation: [],
        capabilityDelegation: [],
        keyAgreement: []
      };

      await saveSecrets(
        {didIdentifier, secretKeys, password: TEST_PASSWORD, secretsDir});

      let error;
      try {
        await loadSecrets(
          {didIdentifier, password: 'wrong-password', secretsDir});
      } catch(e) {
        error = e;
      }
      expect(error).to.exist;
    });
  });

  describe('cel.loadFromFile / cel.read', function() {
    // Build a trustedWitnesses list covering the entire test epoch.
    // TEST_WITNESS_DIDS is populated by mock-witness.js start().
    function getTrustedWitnesses() {
      return TEST_WITNESS_DIDS.map(id => ({
        id,
        validFrom: '2000-01-01T00:00:00Z',
        validUntil: '2099-01-01T00:00:00Z'
      }));
    }

    it('should save and load a valid CEL', async () => {
      const {didDocument, cryptographicEventLog} = await create();
      await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

      const didIdentifier = didDocument.id.replace('did:cel:', '');
      const celPath = join(logsDir, `${didIdentifier}.cel`);
      writeFileSync(celPath, JSON.stringify(cryptographicEventLog, null, 2));

      const {cel, valid, errors, didDocument: loadedDoc} =
        await loadFromFile(
          {filename: celPath, trustedWitnesses: getTrustedWitnesses()});

      expect(valid, `errors: ${JSON.stringify(errors)}`).to.be.true;
      expect(errors).to.have.length(0);
      expect(cel.log).to.have.length(1);
      expect(loadedDoc.id).to.equal(didDocument.id);
    });

    it('should load a multi-event CEL and validate all events', async () => {
      const {keyPair, didDocument, cryptographicEventLog} = await create();
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

      const didIdentifier = didDocument.id.replace('did:cel:', '');
      const celPath = join(logsDir, `${didIdentifier}.cel`);
      writeFileSync(celPath, JSON.stringify(cryptographicEventLog, null, 2));

      const {valid, errors, cel} =
        await loadFromFile(
          {filename: celPath, trustedWitnesses: getTrustedWitnesses()});

      expect(valid, `errors: ${JSON.stringify(errors)}`).to.be.true;
      expect(errors).to.have.length(0);
      expect(cel.log).to.have.length(2);
    });

    it('should resolve historical DID state using versionTime', async () => {
      const {keyPair, didDocument, cryptographicEventLog} = await create();
      await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

      // capture the witness timestamp of the create entry as the cutoff
      const createWitnessTime =
        cryptographicEventLog.log[0].proof[0].created;

      // add a heartbeat entry after a small delay
      const previousEventHash =
        await getPreviousEventHash({cel: cryptographicEventLog});
      const {event: hbEvent} = await createEvent({
        type: 'heartbeat', data: undefined,
        assertionMethod: keyPair, previousEventHash
      });
      await addEvent({cel: cryptographicEventLog, event: hbEvent});
      await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

      const didIdentifier = didDocument.id.replace('did:cel:', '');
      const celPath = join(logsDir, `${didIdentifier}-versiontime.cel`);

      // set the heartbeat's witness timestamp to 1 hour after the create
      const snapshotted = JSON.parse(JSON.stringify(cryptographicEventLog));
      const laterTime = new Date(
        new Date(createWitnessTime).getTime() + 60 * 60 * 1000).toISOString();
      snapshotted.log[1].proof[0].created = laterTime;
      writeFileSync(celPath, JSON.stringify(snapshotted, null, 2));

      // resolving at the create witness time should stop before the heartbeat
      // entry (whose witness timestamp is 1 hour later), so the returned
      // didDocument should match the original create-event document
      const {valid, errors, didDocument: resolvedDoc} = await loadFromFile({
        filename: celPath,
        trustedWitnesses: getTrustedWitnesses(),
        versionTime: createWitnessTime
      });

      expect(valid, `errors: ${JSON.stringify(errors)}`).to.be.true;
      expect(resolvedDoc.id).to.equal(didDocument.id);
    });

    it('should detect a heartbeatFrequency violation', async () => {
      const {keyPair, didDocument, cryptographicEventLog} = await create();
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

      const didIdentifier = didDocument.id.replace('did:cel:', '');
      const celPath = join(logsDir, `${didIdentifier}-hb-violation.cel`);

      // backdate the first entry's witness timestamp to well beyond P10Y
      const violated = JSON.parse(JSON.stringify(cryptographicEventLog));
      const oldDate = new Date(Date.now() - 4000 * 24 * 60 * 60 * 1000);
      violated.log[0].proof[0].created = oldDate.toISOString();
      writeFileSync(celPath, JSON.stringify(violated, null, 2));

      const {valid, errors} =
        await loadFromFile(
          {filename: celPath, trustedWitnesses: getTrustedWitnesses()});

      expect(valid).to.be.false;
      expect(errors.some(e => e.includes('heartbeatFrequency'))).to.be.true;
    });

    it('should enforce a tightened heartbeatFrequency after update',
      async () => {
        // entry 0: create with default P3M
        const {keyPair, didDocument, cryptographicEventLog} = await create();
        await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

        // entry 1: update heartbeatFrequency to P1D
        const {didDocument: updatedDoc} =
        setHeartbeatFrequency({didDocument, heartbeatFrequency: 'P1D'});
        const updateHash =
        await getPreviousEventHash({cel: cryptographicEventLog});
        const {event: updateEvent} = await createEvent({
          type: 'update', data: updatedDoc,
          assertionMethod: keyPair, previousEventHash: updateHash
        });
        await addEvent({cel: cryptographicEventLog, event: updateEvent});
        await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

        // entry 2: heartbeat — gap from entry 1 to entry 2 will be backdated
        // to 2 days, which exceeds the new P1D heartbeatFrequency
        const hbHash = await getPreviousEventHash({cel: cryptographicEventLog});
        const {event: hbEvent} = await createEvent({
          type: 'heartbeat', data: undefined,
          assertionMethod: keyPair, previousEventHash: hbHash
        });
        await addEvent({cel: cryptographicEventLog, event: hbEvent});
        await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

        const didIdentifier = updatedDoc.id.replace('did:cel:', '');
        const celPath = join(logsDir, `${didIdentifier}-p1d-violation.cel`);

        // backdate entry 1's witness timestamp 2 days before entry 2's, so the
        // gap between the witnessed update (entry 1) and heartbeat (entry 2)
        // exceeds the P1D heartbeatFrequency now in effect
        const violated = JSON.parse(JSON.stringify(cryptographicEventLog));
        const entry2Time = new Date(
          violated.log[2].proof[0].created).getTime();
        const backdated = new Date(entry2Time - 2 * 24 * 60 * 60 * 1000);
        violated.log[1].proof[0].created = backdated.toISOString();
        writeFileSync(celPath, JSON.stringify(violated, null, 2));

        const {valid, errors} =
        await loadFromFile(
          {filename: celPath, trustedWitnesses: getTrustedWitnesses()});

        expect(valid).to.be.false;
        expect(errors.some(e => e.includes('heartbeatFrequency'))).to.be.true;
      });

    it('should detect tampering in a saved CEL', async () => {
      const {didDocument, cryptographicEventLog} = await create();
      await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

      const didIdentifier = didDocument.id.replace('did:cel:', '');
      const celPath = join(logsDir, `${didIdentifier}-tampered.cel`);

      // tamper with the DID document inside the event
      const tampered = JSON.parse(JSON.stringify(cryptographicEventLog));
      tampered.log[0].event.operation.data.id = 'did:cel:zTAMPERED';
      writeFileSync(celPath, JSON.stringify(tampered, null, 2));

      const {valid, errors} =
        await loadFromFile(
          {filename: celPath, trustedWitnesses: getTrustedWitnesses()});

      expect(valid).to.be.false;
      expect(errors).to.have.length.at.least(1);
    });

    it('should reject any operation after a deactivate event', async () => {
      const {keyPair, didDocument, cryptographicEventLog} = await create();
      await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

      // append a deactivate event
      const deactivateHash =
        await getPreviousEventHash({cel: cryptographicEventLog});
      const {event: deactivateEvent} = await createEvent({
        type: 'deactivate', data: undefined,
        assertionMethod: keyPair, previousEventHash: deactivateHash
      });
      await addEvent({cel: cryptographicEventLog, event: deactivateEvent});
      await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

      // append a heartbeat after the deactivate (invalid)
      const postDeactivateHash =
        await getPreviousEventHash({cel: cryptographicEventLog});
      const {event: heartbeatEvent} = await createEvent({
        type: 'heartbeat', data: undefined,
        assertionMethod: keyPair, previousEventHash: postDeactivateHash
      });
      await addEvent({cel: cryptographicEventLog, event: heartbeatEvent});
      await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

      const didIdentifier = didDocument.id.replace('did:cel:', '');
      const celPath = join(logsDir, `${didIdentifier}-post-deactivate.cel`);
      writeFileSync(celPath, JSON.stringify(cryptographicEventLog, null, 2));

      const {valid, errors} =
        await loadFromFile(
          {filename: celPath, trustedWitnesses: getTrustedWitnesses()});

      expect(valid).to.be.false;
      expect(errors.some(e => e.includes('after deactivation'))).to.be.true;
    });
  });
});
