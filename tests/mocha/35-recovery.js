/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {
  addEvent, addVm, create, createEvent, getPreviousEventHash,
  hashDidKey, loadFromFile, witness
} from '../../lib/index.js';
import {mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {TEST_WITNESS_DIDS, TEST_WITNESSES} from './helpers.js';
import chai from 'chai';
import {join} from 'node:path';
import {tmpdir} from 'node:os';

const {expect} = chai;

// Build a DID document that uses a recovery key to add a new assertionMethod
// key and rotate the recovery hash. Returns the full CEL and the new key pair.
async function buildRecoveryUpdate({rotateRecovery = true} = {}) {
  const {recoveryKeyPair, didDocument, cryptographicEventLog} =
    await create();
  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

  // add a new assertionMethod key to the DID document
  const {keyPair: newKeyPair, didDocument: docWithNewKey} = await addVm({
    didDocument,
    verificationRelationship: 'assertionMethod'
  });

  // clone the document so we can manipulate recovery independently
  const updatedDoc = JSON.parse(JSON.stringify(docWithNewKey));

  if(rotateRecovery) {
    // generate a new recovery key pair and hash its did:key URI
    const {recoveryKeyPair: newRecoveryKeyPair} = await create();
    const newRecoveryExported = await newRecoveryKeyPair.export(
      {publicKey: true, includeContext: false});
    const newRecoveryDidKey =
      `did:key:${newRecoveryExported.publicKeyMultibase}`;
    const newRecoveryHash = await hashDidKey(newRecoveryDidKey);

    // remove the old recovery hash and add the new one
    const oldHash = await hashDidKey(recoveryKeyPair.id);
    updatedDoc.recovery = updatedDoc.recovery.filter(h => h !== oldHash);
    updatedDoc.recovery.push(newRecoveryHash);
  }
  // (if rotateRecovery is false we leave recovery[] unchanged — bad practice)

  // sign with the recovery key pair (verificationMethod = its did:key URI)
  const previousEventHash =
    await getPreviousEventHash({cel: cryptographicEventLog});
  const {event: recoveryEvent} = await createEvent({
    type: 'update',
    data: updatedDoc,
    assertionMethod: recoveryKeyPair,
    previousEventHash
  });
  await addEvent({cel: cryptographicEventLog, event: recoveryEvent});
  await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

  return {cryptographicEventLog, didDocument: updatedDoc, newKeyPair};
}

describe('recovery', function() {
  this.timeout(120000);

  let logsDir;

  function getTrustedWitnesses() {
    return TEST_WITNESS_DIDS.map(id => ({
      id,
      validFrom: '2000-01-01T00:00:00Z',
      validUntil: '2099-01-01T00:00:00Z'
    }));
  }

  before(() => {
    logsDir = mkdtempSync(join(tmpdir(), 'didcel-recovery-test-'));
  });

  after(() => {
    rmSync(logsDir, {recursive: true, force: true});
  });

  it('should allow a recovery key to add an assertionMethod key and ' +
      'rotate the recovery hash', async () => {
    const {cryptographicEventLog, didDocument} = await buildRecoveryUpdate();

    // the update event must be present and signed by a did:key VM
    const updateEntry = cryptographicEventLog.log[1];
    expect(updateEntry.event.operation.type).to.equal('update');
    const vmRef = updateEntry.event.proof.verificationMethod;
    expect(vmRef).to.match(/^did:key:/);

    // the new document must have two assertionMethod keys
    expect(didDocument.assertionMethod).to.be.an('array').with.length(2);

    // recovery hash must have been rotated (old hash gone, new one present)
    const originalDoc = cryptographicEventLog.log[0].event.operation.data;
    const originalHash = originalDoc.recovery[0];
    expect(didDocument.recovery).to.not.include(originalHash);
    expect(didDocument.recovery).to.have.length(1);

    // save and load must validate cleanly
    const celPath = join(logsDir, 'recovery-positive.cel');
    writeFileSync(celPath, JSON.stringify(cryptographicEventLog, null, 2));
    const {valid, errors} = await loadFromFile(
      {filename: celPath, trustedWitnesses: getTrustedWitnesses()});
    expect(valid, `errors: ${JSON.stringify(errors)}`).to.be.true;
  });

  it('should reject a recovery-key update that does not rotate the ' +
      'recovery hash', async () => {
    const {cryptographicEventLog} =
      await buildRecoveryUpdate({rotateRecovery: false});

    const celPath = join(logsDir, 'recovery-no-rotate.cel');
    writeFileSync(celPath, JSON.stringify(cryptographicEventLog, null, 2));
    const {valid, errors} = await loadFromFile(
      {filename: celPath, trustedWitnesses: getTrustedWitnesses()});

    expect(valid).to.be.false;
    expect(errors.some(e => e.includes('rotating its hash'))).to.be.true;
  });

  it('should reject a recovery-key update after the heartbeatFrequency ' +
      'window has expired', async () => {
    // create with a very tight heartbeatFrequency of P1D
    const {recoveryKeyPair, didDocument, cryptographicEventLog} =
      await create({heartbeatFrequency: 'P1D'});
    await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

    // build the recovery update document (with proper rotation)
    const {didDocument: docWithNewKey} = await addVm({
      didDocument, verificationRelationship: 'assertionMethod'
    });
    const updatedDoc = JSON.parse(JSON.stringify(docWithNewKey));

    // rotate the recovery hash
    const newRecoveryExported = await (await create()).recoveryKeyPair.export(
      {publicKey: true, includeContext: false});
    const newRecoveryDidKey =
      `did:key:${newRecoveryExported.publicKeyMultibase}`;
    const newRecoveryHash = await hashDidKey(newRecoveryDidKey);
    const oldHash = await hashDidKey(recoveryKeyPair.id);
    updatedDoc.recovery = updatedDoc.recovery.filter(h => h !== oldHash);
    updatedDoc.recovery.push(newRecoveryHash);

    const previousEventHash =
      await getPreviousEventHash({cel: cryptographicEventLog});
    const {event: recoveryEvent} = await createEvent({
      type: 'update',
      data: updatedDoc,
      assertionMethod: recoveryKeyPair,
      previousEventHash
    });
    await addEvent({cel: cryptographicEventLog, event: recoveryEvent});
    await witness({cel: cryptographicEventLog, witnesses: TEST_WITNESSES});

    // backdate the first entry's witness timestamp by 2 days so the gap
    // from the create witness to the recovery update witness exceeds P1D
    const violated = JSON.parse(JSON.stringify(cryptographicEventLog));
    const entry1Time = new Date(
      violated.log[1].proof[0].created).getTime();
    const backdated = new Date(entry1Time - 2 * 24 * 60 * 60 * 1000);
    violated.log[0].proof[0].created = backdated.toISOString();

    const celPath = join(logsDir, 'recovery-expired.cel');
    writeFileSync(celPath, JSON.stringify(violated, null, 2));
    const {valid, errors} = await loadFromFile(
      {filename: celPath, trustedWitnesses: getTrustedWitnesses()});

    expect(valid).to.be.false;
    expect(errors.some(e => e.includes('heartbeatFrequency'))).to.be.true;
  });
});
