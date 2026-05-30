/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {TEST_PASSWORD, TEST_WITNESSES} from './helpers.js';
import {
  addEvent, create, createCel, createEvent, load, loadSecrets, saveSecrets,
  witness
} from '../../lib/index.js';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import chai from 'chai';

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

  describe('cel.load', function() {
    it('should save and load a valid CEL', async () => {
      const {event, didDocument} = await create();
      const cryptoEventLog = createCel({event});
      await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});

      const didIdentifier = didDocument.id.replace('did:cel:', '');
      const celPath = join(logsDir, `${didIdentifier}.cel`);
      writeFileSync(celPath, JSON.stringify(cryptoEventLog, null, 2));

      const {cel, valid, errors, didDocument: loadedDoc} =
        await load({filename: celPath});

      expect(valid, `errors: ${JSON.stringify(errors)}`).to.be.true;
      expect(errors).to.have.length(0);
      expect(cel.log).to.have.length(1);
      expect(loadedDoc.id).to.equal(didDocument.id);
    });

    it('should load a multi-event CEL and validate all events', async () => {
      const {keyPair, event, didDocument} = await create();
      const cryptoEventLog = createCel({event});
      await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});

      const {event: hbEvent} = await createEvent({
        type: 'heartbeat',
        data: undefined,
        assertionMethod: keyPair
      });
      await addEvent({cel: cryptoEventLog, event: hbEvent});
      await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});

      const didIdentifier = didDocument.id.replace('did:cel:', '');
      const celPath = join(logsDir, `${didIdentifier}.cel`);
      writeFileSync(celPath, JSON.stringify(cryptoEventLog, null, 2));

      const {valid, errors, cel} = await load({filename: celPath});

      expect(valid, `errors: ${JSON.stringify(errors)}`).to.be.true;
      expect(errors).to.have.length(0);
      expect(cel.log).to.have.length(2);
    });

    it('should detect tampering in a saved CEL', async () => {
      const {event, didDocument} = await create();
      const cryptoEventLog = createCel({event});
      await witness({cel: cryptoEventLog, witnesses: TEST_WITNESSES});

      const didIdentifier = didDocument.id.replace('did:cel:', '');
      const celPath = join(logsDir, `${didIdentifier}-tampered.cel`);

      // tamper with the DID document inside the event
      const tampered = JSON.parse(JSON.stringify(cryptoEventLog));
      tampered.log[0].event.operation.data.id = 'did:cel:zTAMPERED';
      writeFileSync(celPath, JSON.stringify(tampered, null, 2));

      const {valid, errors} = await load({filename: celPath});

      expect(valid).to.be.false;
      expect(errors).to.have.length.at.least(1);
    });
  });
});