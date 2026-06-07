/**
 * @file Cryptographic Event Log (CEL) management.
 * This module provides functions for creating, updating, and witnessing events
 * in a Cryptographic Event Log, which maintains a cryptographically verifiable
 * chain of events for DID document operations.
 */

import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as witnessService from './witness.js';
import {gunzipSync, gzipSync} from 'node:zlib';
import {readFileSync, writeFileSync} from 'node:fs';
import {assertValidCel} from './validate.js';
import {decode as base58Decode} from 'base58-universal';
import canonicalize from 'canonicalize';
import crypto from 'node:crypto';
import {hashDidKey} from './didcel.js';
import moment from 'moment';
import {sha3256Multibase} from './utils.js';
import {sha3_256} from '@noble/hashes/sha3.js';

/**
 * Creates a new Cryptographic Event Log (CEL) with an initial 'create' event.
 * The log maintains a chain of events that document the history of DID ops.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.event - The data for the create operation.
 * @returns {object} A new CEL object with the structure:
 *   - log: Array containing the initial create event.
 *
 * @example
 * const cel = create({
 *   event,
 * });
 */
export function create({event}) {
  // initialize the log with a create operation event
  const log = {
    log: [{
      event
    }]
  };

  return log;
}

/**
 * Generates witness proofs for the most recent event in a CEL.
 * Each configured witness creates a cryptographic proof attesting to the event.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.cel - The Cryptographic Event Log containing events
 *   to witness.
 * @param {Array<string>} options.witnesses - Array of witness service URLs.
 * @returns {Promise<Array>} An array of proof objects, one from each witness.
 *
 * @example
 * const proofs = await witness({cel: myCel, witnesses: ['https://...']});
 */
export async function witness({cel, witnesses}) {
  if(!cel.log || cel.log.length === 0) {
    const err = new Error(
      'Cannot witness an empty CEL log - use cel.create() first');
    err.name = 'MALFORMED_CEL_ERROR';
    throw err;
  }
  const logEntry = cel.log[cel.log.length - 1];

  // canonicalize and hash the bare event (not the log entry wrapper) to
  // produce the digestMultibase, per the spec witness algorithm
  const digestMultibase = await sha3256Multibase(canonicalize(logEntry.event));

  const witnessUrls = witnesses;
  if(!Array.isArray(witnessUrls) || witnessUrls.length === 0) {
    throw new Error('No witnesses provided.');
  }

  let proofs;
  try {
    proofs = await Promise.all(witnessUrls.map(
      witnessUrl => witnessService.witness({digestMultibase, witnessUrl})));
  } catch(e) {
    const err = new Error(`Witnessing failed: ${e.message}`);
    err.name = 'WITNESSING_ERROR';
    throw err;
  }

  logEntry.proof = proofs;

  return logEntry.proof;
}

export async function getPreviousEventHash({cel}) {
  if(cel.log.length === 0) {
    return undefined;
  }
  const lastEvent = cel.log[cel.log.length - 1].event;
  return sha3256Multibase(canonicalize(lastEvent));
}

/**
 * Adds an event to an existing CEL, creating a hash-linked chain of
 * events. The update event includes a hash of the previous event to ensure log
 * integrity.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.cel - The Certificate Event Log to add the event to.
 * @param {object} options.event - The data for the update operation (typically
 *   an updated DID document).
 * @returns {Promise<object>} The updated CEL with the new event appended.
 *
 * @example
 * const updatedCel = await addEvent({
 *   cel: existingCel,
 *   data: modifiedDidDocument
 * });
 */
export async function addEvent({cel, event}) {
  if(!cel.log || cel.log.length === 0) {
    const err = new Error(
      'Cannot add event to an empty CEL log - use cel.create() first');
    err.name = 'MALFORMED_CEL_ERROR';
    throw err;
  }
  // deactivation is a terminal operation; no further events are permitted
  const isDeactivated = cel.log.some(
    entry => entry.event?.operation?.type === 'deactivate');
  if(isDeactivated) {
    const err = new Error(
      'Cannot add event to a deactivated CEL - deactivation is terminal');
    err.name = 'MALFORMED_CEL_ERROR';
    throw err;
  }
  // previousEventHash must already be set on the event (and covered by the
  // operation proof) before calling this function
  cel.log.push({event});

  assertValidCel({cel});

  return cel;
}

/**
 * Reads and fully validates a Cryptographic Event Log. Checks:
 * - DID identifier self-certifying property
 * - Hash chain integrity (previousEventHash on each non-create entry)
 * - Operation proof signatures (ecdsa-jcs-2019 via manual JCS verification)
 * - Witness proof signatures (blind-witness manual JCS verification)
 * - Timestamp deviation between operation proof and witness proofs (<= 5 min).
 * - Heartbeat frequency compliance across consecutive witnessed entries.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.cel - The parsed Cryptographic Event Log.
 * @param {Array<object>} [options.trustedWitnesses=[]] - Trusted witnesses.
 *   Each entry: {id, validFrom, validUntil}. Only proofs whose
 *   verificationMethod DID matches an entry and whose created falls within
 *   validFrom/validUntil are verified. Unknown witnesses are ignored.
 * @param {string|null} [options.versionTime=null] - Optional ISO datetime. When
 *   set, log entries whose earliest trusted witness timestamp exceeds this time
 *   are excluded, enabling historical DID document resolution.
 * @returns {Promise<object>} An object with:
 *   - cel: The CEL object.
 *   - errors: Array of error strings (empty if valid).
 *   - valid: Boolean, true if no errors.
 *   - didDocument: The most recent DID document state (or null).
 */
export async function read({cel, trustedWitnesses = [], versionTime = null}) {
  const errors = [];
  let currentDidDocument = null;
  // latest witness timestamp for the previous log entry, used for heartbeat
  // frequency checks at each subsequent entry boundary
  let prevEntryWitnessTime = null;

  // Validate the CEL structure before processing.
  try {
    assertValidCel({cel});
  } catch(e) {
    errors.push(e.message);
    return {cel, errors, valid: false, didDocument: null};
  }

  // Verify the self-certifying DID identifier: the DID must equal
  // did:cel: + base58btc(SHA3-256(JCS(first event without proof))).
  if(cel.log.length === 0) {
    errors.push('CEL log is empty');
    return {cel, errors, valid: false, didDocument: null};
  }
  const firstEvent = cel.log[0].event;
  // The DID identifier is derived from the SHA3-256 hash of the canonicalized
  // DID document *before* `id` and verification method `controller` values were
  // set (per the create algorithm). Reconstruct that pre-id document from the
  // event by removing `id` and `controller` from all embedded verification
  // methods, which mirrors the document state at hash time.
  const firstDidDocument = structuredClone(firstEvent?.operation?.data ?? {});
  delete firstDidDocument.id;
  for(const rel of ['assertionMethod', 'authentication', 'keyAgreement',
    'capabilityDelegation', 'capabilityInvocation']) {
    if(Array.isArray(firstDidDocument[rel])) {
      for(const vm of firstDidDocument[rel]) {
        if(typeof vm === 'object') {
          delete vm.controller;
        }
      }
    }
  }
  const expectedId =
    'did:cel:' + await sha3256Multibase(canonicalize(firstDidDocument));
  const claimedId = firstEvent?.operation?.data?.id;
  if(claimedId !== expectedId) {
    errors.push(
      `DID identifier mismatch: claimed "${claimedId}", ` +
      `expected "${expectedId}"`);
  }

  let deactivated = false;

  for(let i = 0; i < cel.log.length; i++) {
    const logEntry = cel.log[i];
    const event = logEntry.event;
    const opProof = event.proof;
    const witnessProofs = logEntry.proof ?? [];

    // Reject any entry that appears after a deactivate event - deactivation
    // is a terminal operation and no further operations are valid.
    if(deactivated) {
      errors.push(
        `entry ${i}: operation after deactivation is not permitted`);
      continue;
    }

    // 1. Verify previousEventHash for all entries after the first
    if(i > 0) {
      const computed = await getPreviousEventHash(
        {cel: {log: cel.log.slice(0, i)}});
      if(computed !== event.previousEventHash) {
        errors.push(
          `entry ${i}: previousEventHash mismatch ` +
          `(expected ${computed}, got ${event.previousEventHash})`);
      }
    }

    // Snapshot the document state from the previous entry before advancing.
    // The heartbeatFrequency check (step 5) must use the frequency that was
    // in effect during the gap leading into this entry, not any new frequency
    // introduced by this entry's update.
    const prevDidDocument = currentDidDocument;

    // Track the current DID document for key lookup on stateless events
    if(event.operation?.data) {
      currentDidDocument = event.operation.data;
    }

    // Mark the DID as deactivated after processing this entry so that any
    // subsequent entries are rejected at the top of the next iteration.
    if(event.operation?.type === 'deactivate') {
      deactivated = true;
    }

    // 2. Verify the operation proof.
    // assertionMethod keys are looked up in currentDidDocument (the new state
    // introduced by this entry). Recovery keys must be looked up in
    // prevDidDocument - the state that was in effect before this update, where
    // the recovery hash still exists (the update will rotate it out).
    if(opProof) {
      try {
        const verified = await _verifyOperationProof(
          {event, opProof, currentDidDocument,
            prevDidDocument: prevDidDocument ?? currentDidDocument});
        if(!verified) {
          errors.push(`entry ${i}: operation proof invalid`);
        }
      } catch(e) {
        errors.push(`entry ${i}: operation proof error: ${e.message}`);
      }
    }

    // 3. Filter witness proofs to only those from trusted witnesses whose
    // validFrom/validUntil window brackets the proof's created timestamp.
    const trustedWitnessProofs = witnessProofs.filter(
      wp => _isTrustedWitnessProof({wp, trustedWitnesses}));

    // versionTime cutoff: if a versionTime is set and all trusted witness
    // proofs for this entry are after the requested time, stop processing here.
    if(versionTime !== null && trustedWitnessProofs.length > 0) {
      const versionTimeMs = new Date(versionTime).getTime();
      const earliestWitnessTime = Math.min(
        ...trustedWitnessProofs.map(wp => new Date(wp.created).getTime()));
      if(earliestWitnessTime > versionTimeMs) {
        break;
      }
    }

    // verify each trusted witness proof and check timestamp deviation
    const opTime = opProof?.created ?
      new Date(opProof.created).getTime() : null;
    let entryWitnessTime = null;
    for(let j = 0; j < trustedWitnessProofs.length; j++) {
      const witnessProof = trustedWitnessProofs[j];

      try {
        const verified = await _verifyWitnessProof({logEntry, witnessProof});
        if(!verified) {
          errors.push(`entry ${i} witness ${j}: invalid signature`);
        }
      } catch(e) {
        errors.push(`entry ${i} witness ${j}: error: ${e.message}`);
      }

      // witness proofs MUST have a created timestamp
      if(!witnessProof.created) {
        errors.push(
          `entry ${i} witness ${j}: missing required created timestamp`);
      } else {
        const wTime = new Date(witnessProof.created).getTime();
        // always track the latest trusted witness timestamp for heartbeat
        if(entryWitnessTime === null || wTime > entryWitnessTime) {
          entryWitnessTime = wTime;
        }
        // 4. Timestamp deviation <= 5 minutes (requires operation proof time)
        if(opTime !== null) {
          const diffMinutes = Math.abs(opTime - wTime) / 60000;
          if(diffMinutes > 5) {
            errors.push(
              `entry ${i} witness ${j}: timestamp deviation ` +
              `${diffMinutes.toFixed(1)}min exceeds 5min limit`);
          }
        }
      }
    }

    // 6. If the operation was signed by a recovery key, verify that the new
    // DID document no longer contains that recovery hash (it must be rotated
    // out) and contains at least one new recovery hash.
    if(opProof && currentDidDocument) {
      const vmRef = opProof.verificationMethod;
      if(vmRef?.startsWith('did:key:')) {
        const didKeyId = vmRef.split('#')[0];
        const usedHash = await hashDidKey(didKeyId);
        const prevRecovery = prevDidDocument?.recovery ?? [];
        const newRecovery = currentDidDocument?.recovery ?? [];
        if(prevRecovery.includes(usedHash)) {
          if(newRecovery.includes(usedHash)) {
            errors.push(
              `entry ${i}: recovery key used without rotating its hash - ` +
              `${usedHash} must be removed from recovery[]`);
          }
          if(newRecovery.length < prevRecovery.length) {
            errors.push(
              `entry ${i}: recovery key rotation must add a new recovery ` +
              `hash to replace the consumed one`);
          }
        }
      }
    }

    // 5. Check heartbeatFrequency: for each entry after the first, the elapsed
    // time from the previous entry's latest witness timestamp to this entry's
    // latest witness timestamp must not exceed the heartbeatFrequency duration.
    // If heartbeatFrequency is not set, the default is P10Y (10 years).
    // This check applies to all event types including deactivate - a DID is
    // automatically considered deactivated once the window expires, so an
    // explicit deactivate arriving after the window is still a violation.
    // Use the frequency from the previous document state so a tightened
    // heartbeatFrequency introduced by this entry is not applied retroactively
    // to the gap that preceded it.
    const heartbeatFrequency =
      (prevDidDocument ?? currentDidDocument)?.heartbeatFrequency ?? 'P10Y';
    if(i > 0 && prevEntryWitnessTime !== null && entryWitnessTime !== null) {
      const freq = moment.duration(heartbeatFrequency);
      const elapsed = entryWitnessTime - prevEntryWitnessTime;
      if(elapsed > freq.asMilliseconds()) {
        const elapsedDuration = moment.duration(elapsed).humanize();
        errors.push(
          `entry ${i}: heartbeatFrequency violation - ` +
          `${elapsedDuration} elapsed since previous witnessed event ` +
          `exceeds ${heartbeatFrequency}`);
      }
    }

    // advance the previous entry witness time for the next iteration
    if(entryWitnessTime !== null) {
      prevEntryWitnessTime = entryWitnessTime;
    }
  }

  const valid = errors.length === 0;
  return {cel, errors, valid, didDocument: valid ? currentDidDocument : null};
}

/**
 * Returns true if a witness proof comes from a trusted witness whose
 * validFrom/validUntil window brackets the proof's created timestamp.
 *
 * @param {object} options - Options.
 * @param {object} options.wp - The witness proof to evaluate.
 * @param {Array<object>} options.trustedWitnesses - Trusted witness entries.
 * @returns {boolean} True if the proof is from a valid trusted witness.
 */
function _isTrustedWitnessProof({wp, trustedWitnesses}) {
  const vmDid = wp.verificationMethod?.split('#')[0];
  const entry = trustedWitnesses.find(tw => tw.id === vmDid);
  if(!entry) {
    return false;
  }
  const created = wp.created ? new Date(wp.created).getTime() : null;
  const validFrom = entry.validFrom ?
    new Date(entry.validFrom).getTime() : null;
  const validUntil = entry.validUntil ?
    new Date(entry.validUntil).getTime() : null;
  if(created === null) {
    return false;
  }
  if(validFrom !== null && created < validFrom) {
    return false;
  }
  if(validUntil !== null && created > validUntil) {
    return false;
  }
  return true;
}

/**
 * Verifies an operation proof using the ecdsa-jcs-2019 manual JCS approach.
 * VerifyData = SHA256(JCS(proofOptions_without_proofValue)) ||
 * SHA256(JCS(event_without_proof)).
 *
 * @param {object} options - Options.
 * @param {object} options.event - The event object.
 * @param {object} options.opProof - The operation proof.
 * @param {object} options.currentDidDocument - The current DID document state.
 * @param {object} options.prevDidDocument - The previous DID document state.
 * @returns {Promise<boolean>} True if the proof is valid.
 */
async function _verifyOperationProof(
  {event, opProof, currentDidDocument, prevDidDocument}) {
  const vmRef = opProof.verificationMethod;

  // try assertionMethod first; if not found, check recovery keys
  const assertionKey = _findAssertionKey(
    {vmRef, didDocument: currentDidDocument});

  let publicKeyMultibase;
  let keyController;

  if(assertionKey) {
    // normal assertionMethod path
    publicKeyMultibase = assertionKey.publicKeyMultibase;
    keyController = currentDidDocument.id;
  } else if(vmRef.startsWith('did:key:')) {
    // recovery key path: hash the did:key URI and check it against the
    // recovery[] of the *previous* document - the update will rotate it out,
    // so it is absent from currentDidDocument by the time we verify
    const didKeyId = vmRef.split('#')[0];
    const hash = await hashDidKey(didKeyId);
    const recovery = prevDidDocument?.recovery ?? [];
    if(!recovery.includes(hash)) {
      throw new Error(
        `verification method not found in DID document: ${vmRef}`);
    }
    // the public key is self-describing in the did:key URI
    publicKeyMultibase = didKeyId.replace('did:key:', '');
    keyController = didKeyId;
  } else {
    throw new Error(
      `verification method not found in DID document: ${vmRef}`);
  }

  // exclude only the proof itself from the doc hash; previousEventHash is
  // set before signing and is therefore covered by the operation proof
  const doc = {...event};
  delete doc.proof;
  const proofOptions = {...opProof};
  delete proofOptions.proofValue;

  const c14nDoc = canonicalize(doc);
  const c14nProof = canonicalize(proofOptions);
  const proofHash = new Uint8Array(
    crypto.createHash('sha256').update(c14nProof).digest());
  const docHash = new Uint8Array(
    crypto.createHash('sha256').update(c14nDoc).digest());

  const verifyData = new Uint8Array(proofHash.length + docHash.length);
  verifyData.set(proofHash, 0);
  verifyData.set(docHash, proofHash.length);

  const keyPair = await EcdsaMultikey.from({
    type: 'Multikey',
    id: vmRef,
    controller: keyController,
    publicKeyMultibase
  });
  const verifier = keyPair.verifier();
  const sigBytes = base58Decode(opProof.proofValue.slice(1));
  return verifier.verify({data: verifyData, signature: sigBytes});
}

/**
 * Verifies a witness proof using hmbd's blind-witness signing scheme.
 * VerifyData = SHA256(JCS(proofOptions_without_proofValue)) || rawHash
 * where rawHash = SHA256 bytes from digestMultibase of the log entry.
 *
 * @param {object} options - Options.
 * @param {object} options.logEntry - The full log entry {event, proof[]}.
 * @param {object} options.witnessProof - The witness proof to verify.
 * @returns {Promise<boolean>} True if the proof is valid.
 */
async function _verifyWitnessProof({logEntry, witnessProof}) {
  const utf8Encoder = new TextEncoder();

  // reconstruct the digestMultibase from the bare event object
  // (same as what was sent to the witness service)
  const canonicalized = canonicalize(logEntry.event);
  const rawHashFull = sha3_256(utf8Encoder.encode(canonicalized));

  // build proofHash from the witness proof options (without proofValue)
  const proofOptions = {...witnessProof};
  delete proofOptions.proofValue;
  const c14nProof = canonicalize(proofOptions);
  const proofHash = new Uint8Array(
    crypto.createHash('sha256').update(c14nProof).digest());

  // verifyData = SHA256(c14n(proofOptions)) || rawHash
  const verifyData = new Uint8Array(proofHash.length + rawHashFull.length);
  verifyData.set(proofHash, 0);
  verifyData.set(rawHashFull, proofHash.length);

  // witness proofs must declare assertionMethod as their proof purpose
  if(witnessProof.proofPurpose !== 'assertionMethod') {
    throw new Error(
      `witness proof proofPurpose must be "assertionMethod", ` +
      `got "${witnessProof.proofPurpose}"`);
  }

  // extract public key from did:key: verificationMethod
  const vmId = witnessProof.verificationMethod;
  const didKeyId = vmId.split('#')[0];
  const publicKeyMultibase = didKeyId.replace('did:key:', '');

  const keyPair = await EcdsaMultikey.from({
    type: 'Multikey',
    id: vmId,
    controller: didKeyId,
    publicKeyMultibase
  });
  const verifier = keyPair.verifier();
  const sigBytes = base58Decode(witnessProof.proofValue.slice(1));
  return verifier.verify({data: verifyData, signature: sigBytes});
}

/**
 * Finds the assertionMethod key in a DID document that matches a VM reference.
 *
 * @param {object} options - Options.
 * @param {string} options.vmRef - The verificationMethod reference to find.
 * @param {object} options.didDocument - The DID document to search.
 * @returns {object|null} The matching key object, or null if not found.
 */
function _findAssertionKey({vmRef, didDocument}) {
  if(!didDocument?.assertionMethod) {
    return null;
  }
  for(const key of didDocument.assertionMethod) {
    if(typeof key !== 'object') {
      continue;
    }
    // match by full id or by fragment suffix
    const fullId = didDocument.id + key.id;
    if(fullId === vmRef || key.id === vmRef) {
      return key;
    }
  }
  return null;
}

/**
 * Loads a Cryptographic Event Log from a file and fully validates it.
 * Convenience wrapper around read() for file-based access.
 *
 * @param {object} options - Configuration options.
 * @param {string} options.filename - Path to the .cel file to load.
 * @param {Array<object>} [options.trustedWitnesses=[]] - See read().
 * @param {string|null} [options.versionTime=null] - See read().
 * @returns {Promise<object>} See read() return value.
 */
export async function loadFromFile(
  {filename, trustedWitnesses = [], versionTime = null}) {
  const compressed = readFileSync(filename);
  const cel = JSON.parse(gunzipSync(compressed).toString('utf8'));
  return read({cel, trustedWitnesses, versionTime});
}

/**
 * Saves a Cryptographic Event Log to a gzip-compressed file.
 * All CELs MUST be transmitted using gzip compression per the spec.
 *
 * @param {object} options - Configuration options.
 * @param {string} options.filename - Path to write the .cel file to.
 * @param {object} options.cel - The CEL object to serialize and compress.
 */
export function saveToFile({filename, cel}) {
  const compressed = gzipSync(Buffer.from(JSON.stringify(cel), 'utf8'));
  writeFileSync(filename, compressed);
}

export default {addEvent, create, loadFromFile, read, saveToFile, witness};
