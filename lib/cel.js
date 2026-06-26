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
 * const cel = create({event});
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

/**
 * Returns the SHA3-256 multibase hash of the most recent event in a CEL.
 * This value is placed in `previousEventHash` on the next event before
 * signing, so the hash chain is covered by the operation proof.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.cel - The Cryptographic Event Log.
 * @returns {Promise<string|undefined>} Base58btc multibase-encoded SHA3-256
 *   multihash of the last event, or undefined if the log is empty.
 */
export async function getPreviousEventHash({cel}) {
  if(cel.log.length === 0) {
    return undefined;
  }
  const lastEvent = cel.log[cel.log.length - 1].event;
  return sha3256Multibase(canonicalize(lastEvent));
}

/**
 * Adds a pre-signed event to an existing CEL, extending the hash-linked chain.
 * The caller must compute `previousEventHash` via `getPreviousEventHash()` and
 * include it in the event before signing, so the hash is covered by the proof.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.cel - The Cryptographic Event Log to append to.
 * @param {object} options.event - The signed event object to append (any
 *   operation type: update, heartbeat, or deactivate).
 * @returns {Promise<object>} The updated CEL with the new event appended.
 *
 * @example
 * const updatedCel = await addEvent({
 *   cel: existingCel,
 *   event: signedEvent
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
 * - Heartbeat key rotation enforcement when a heartbeat key signs an event.
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
  // Validate the CEL structure before processing.
  try {
    assertValidCel({cel});
  } catch(e) {
    return {cel, errors: [e.message], valid: false, didDocument: null};
  }

  if(cel.log.length === 0) {
    return {cel, errors: ['CEL log is empty'], valid: false, didDocument: null};
  }

  // Verify the self-certifying DID identifier.
  const idErr = await _verifySelfCertifyingId({firstEvent: cel.log[0].event});
  if(idErr) {
    return {cel, errors: [idErr], valid: false, didDocument: null};
  }

  let currentDidDocument = null;
  // latest witness timestamp for the previous log entry, used for heartbeat
  // frequency checks at each subsequent entry boundary
  let prevEntryWitnessTime = null;
  let deactivated = false;
  // witness errors from the previous entry, held until this entry's
  // heartbeatFrequency check runs — a frequency violation supersedes them
  let pendingWitnessErrors = null;

  for(let i = 0; i < cel.log.length; i++) {
    const logEntry = cel.log[i];
    const event = logEntry.event;
    const opProof = event.proof;
    const witnessProofs = logEntry.proof ?? [];

    // Reject any entry that appears after a deactivate event - deactivation
    // is a terminal operation and no further operations are valid.
    if(deactivated) {
      return {
        cel,
        errors: [`entry ${i}: operation after deactivation is not permitted`],
        valid: false,
        didDocument: null
      };
    }

    // Filter witness proofs to only those from trusted witnesses whose
    // validFrom/validUntil window brackets the proof's created timestamp.
    const trustedWitnessProofs = witnessProofs.filter(
      wp => _isTrustedWitnessProof({wp, trustedWitnesses}));

    // versionTime cutoff: skip this entry and all subsequent entries when the
    // earliest trusted witness timestamp is after the requested versionTime.
    // This check MUST happen before any state mutations (currentDidDocument,
    // deactivated) so that a skipped entry never contaminates the verified
    // state returned to the caller. An attacker who can write a future-dated
    // entry to CEL storage must not be able to have its unverified document
    // returned simply by choosing a versionTime that triggers the break after
    // currentDidDocument is already overwritten.
    if(versionTime !== null && trustedWitnessProofs.length > 0) {
      const versionTimeMs = new Date(versionTime).getTime();
      const earliestWitnessTime = Math.min(
        ...trustedWitnessProofs.map(wp => new Date(wp.created).getTime()));
      if(earliestWitnessTime > versionTimeMs) {
        break;
      }
    }

    // Verify previousEventHash for all entries after the first.
    if(i > 0) {
      const chainErr = await _verifyHashChain({cel, i, event});
      if(chainErr) {
        return {cel, errors: [chainErr], valid: false, didDocument: null};
      }
    }

    // Snapshot the document state from the previous entry before advancing.
    // The heartbeatFrequency check must use the frequency that was in effect
    // during the gap leading into this entry, not any new frequency introduced
    // by this entry's update.
    const prevDidDocument = currentDidDocument;
    currentDidDocument = _advanceDidDocument({currentDidDocument, event});

    // Mark the DID as deactivated after processing this entry so that any
    // subsequent entries are rejected at the top of the next iteration.
    if(event.operation?.type === 'deactivate') {
      deactivated = true;
    }

    // Verify the operation proof.
    // Keys must be looked up in the *previously verified* document state, not
    // the document introduced by this entry. Using the new document for key
    // lookup would allow an attacker to insert a new key in an update, sign
    // the update with that key, and have the verifier accept it circularly.
    // Exception: the create event (i === 0) has no prior state; the
    // self-certifying identifier check already pins its document integrity.
    const verifyDidDocument = i === 0 ? currentDidDocument : prevDidDocument;
    const opProofErr = await _verifyOperationProofEntry(
      {i, event, opProof, verifyDidDocument, prevDidDocument});
    if(opProofErr) {
      return {cel, errors: [opProofErr], valid: false, didDocument: null};
    }

    // For every operation except create (i===0) and deactivate, verify that
    // the signing heartbeat key's hash has been rotated out and a new one added.
    const rotationErr = await _checkHeartbeatRotation(
      {i, event, opProof, prevDidDocument, currentDidDocument});
    if(rotationErr) {
      return {cel, errors: [rotationErr], valid: false, didDocument: null};
    }

    // Verify each trusted witness proof and check timestamp deviation.
    // entryWitnessTime is always propagated to prevEntryWitnessTime, even when
    // proofs fail signature verification. A backdated-but-invalid witness
    // timestamp causes the *next* entry's heartbeatFrequency check to fire as
    // the root-cause error, superseding the signature error on this entry.
    // Witness errors are therefore held in pendingWitnessErrors and only
    // returned after the next entry's frequency check has had a chance to run.
    const {errors: witnessErrors, entryWitnessTime} =
      await _verifyWitnessProofsEntry({i, logEntry, trustedWitnessProofs, opProof});

    // Check that the elapsed time since the previous witnessed entry does not
    // exceed the heartbeatFrequency duration in effect for this gap.
    // If a frequency violation is found here, it supersedes any pending witness
    // errors from the prior entry (the backdated timestamp is the root cause).
    const freqErr = _checkHeartbeatFrequency(
      {i, prevEntryWitnessTime, entryWitnessTime, prevDidDocument,
        currentDidDocument});
    if(freqErr) {
      return {cel, errors: [freqErr], valid: false, didDocument: null};
    }

    // No frequency violation: return any witness errors that were pending from
    // the prior entry (they were not superseded by a frequency error).
    if(pendingWitnessErrors) {
      return {cel, errors: pendingWitnessErrors, valid: false, didDocument: null};
    }

    // Advance the previous entry witness time for the next iteration.
    if(entryWitnessTime !== null) {
      prevEntryWitnessTime = entryWitnessTime;
    }

    // Hold this entry's witness errors until the next entry's frequency check.
    pendingWitnessErrors = witnessErrors.length > 0 ? witnessErrors : null;
  }

  // Return any witness errors from the final entry (no subsequent entry to
  // provide a frequency check that might supersede them).
  if(pendingWitnessErrors) {
    return {cel, errors: pendingWitnessErrors, valid: false, didDocument: null};
  }

  return {cel, errors: [], valid: true, didDocument: currentDidDocument};
}

/**
 * Verifies the self-certifying DID identifier of the first event.
 * The DID must equal did:cel: + base58btc(SHA3-256(JCS(doc without id/controllers))).
 *
 * @param {object} options - Options.
 * @param {object} options.firstEvent - The first log entry's event.
 * @returns {Promise<string|null>} Error message, or null if valid.
 */
async function _verifySelfCertifyingId({firstEvent}) {
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
    return `DID identifier mismatch: claimed "${claimedId}", ` +
      `expected "${expectedId}"`;
  }
  return null;
}

/**
 * Verifies that event.previousEventHash matches the hash of the prior event.
 *
 * @param {object} options - Options.
 * @param {object} options.cel - The full CEL.
 * @param {number} options.i - Index of the current entry (must be > 0).
 * @param {object} options.event - The current event.
 * @returns {Promise<string|null>} Error message, or null if valid.
 */
async function _verifyHashChain({cel, i, event}) {
  const computed = await getPreviousEventHash({cel: {log: cel.log.slice(0, i)}});
  if(computed !== event.previousEventHash) {
    return `entry ${i}: previousEventHash mismatch ` +
      `(expected ${computed}, got ${event.previousEventHash})`;
  }
  return null;
}

/**
 * Returns the new DID document state after applying an event's operation.
 * Heartbeat events carry only a partial update (new heartbeat array), so they
 * merge into the existing document rather than replacing it.
 *
 * @param {object} options - Options.
 * @param {object|null} options.currentDidDocument - Current document state.
 * @param {object} options.event - The event being applied.
 * @returns {object|null} Updated document state.
 */
function _advanceDidDocument({currentDidDocument, event}) {
  if(!event.operation?.data) {
    return currentDidDocument;
  }
  if(event.operation.type === 'heartbeat') {
    return {...currentDidDocument, heartbeat: event.operation.data.heartbeat};
  }
  return event.operation.data;
}

/**
 * Verifies the operation proof for a single log entry.
 * Every event must carry a proof — a missing proof is always a hard error.
 * Keys are looked up in verifyDidDocument (the previously verified state) to
 * prevent circular key-introduction attacks.
 *
 * @param {object} options - Options.
 * @param {number} options.i - Log entry index.
 * @param {object} options.event - The event object.
 * @param {object} options.opProof - The operation proof (may be undefined).
 * @param {object} options.verifyDidDocument - Document to look up keys in.
 * @param {object|null} options.prevDidDocument - Previous document state.
 * @returns {Promise<string|null>} Error message, or null if valid.
 */
async function _verifyOperationProofEntry(
  {i, event, opProof, verifyDidDocument, prevDidDocument}) {
  if(!opProof) {
    return `entry ${i}: operation proof is missing`;
  }
  try {
    const verified = await _verifyOperationProof(
      {event, opProof, prevDidDocument: prevDidDocument ?? verifyDidDocument});
    if(!verified) {
      return `entry ${i}: operation proof invalid`;
    }
  } catch(e) {
    return `entry ${i}: operation proof error: ${e.message}`;
  }
  return null;
}

/**
 * Verifies all trusted witness proofs for a single log entry and checks that
 * each witness timestamp deviates from the operation proof time by at most 5 min.
 *
 * @param {object} options - Options.
 * @param {number} options.i - Log entry index.
 * @param {object} options.logEntry - The full log entry {event, proof[]}.
 * @param {Array} options.trustedWitnessProofs - Pre-filtered trusted proofs.
 * @param {object} options.opProof - The operation proof (for timestamp check).
 * @returns {Promise<{errors: string[], entryWitnessTime: number|null}>}
 */
async function _verifyWitnessProofsEntry(
  {i, logEntry, trustedWitnessProofs, opProof}) {
  const errors = [];
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

    if(!witnessProof.created) {
      errors.push(
        `entry ${i} witness ${j}: missing required created timestamp`);
    } else {
      const wTime = new Date(witnessProof.created).getTime();
      if(entryWitnessTime === null || wTime > entryWitnessTime) {
        entryWitnessTime = wTime;
      }
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

  return {errors, entryWitnessTime};
}

/**
 * Checks that the heartbeat key used to sign an event has been rotated:
 * its hash must be removed from heartbeat[] and a new hash added.
 * Applies to all events after create and before/including deactivate.
 *
 * @param {object} options - Options.
 * @param {number} options.i - Log entry index.
 * @param {object} options.event - The event object.
 * @param {object} options.opProof - The operation proof.
 * @param {object|null} options.prevDidDocument - Document state before this entry.
 * @param {object|null} options.currentDidDocument - Document state after this entry.
 * @returns {Promise<string|null>} Error message, or null if valid.
 */
async function _checkHeartbeatRotation(
  {i, event, opProof, prevDidDocument, currentDidDocument}) {
  // Deactivate is terminal so no rotation check is needed; the create event
  // establishes the initial heartbeat state with no predecessor to rotate.
  if(!opProof || !currentDidDocument || i === 0 ||
      event.operation?.type === 'deactivate') {
    return null;
  }
  const vmRef = opProof.verificationMethod;
  if(!vmRef?.startsWith('did:key:')) {
    return null;
  }
  const didKeyId = vmRef.split('#')[0];
  const usedHash = await hashDidKey(didKeyId);
  const prevHeartbeat = prevDidDocument?.heartbeat ?? [];
  const newHeartbeat = currentDidDocument?.heartbeat ?? [];
  if(prevHeartbeat.includes(usedHash)) {
    if(newHeartbeat.includes(usedHash)) {
      return `entry ${i}: heartbeat key used without rotating its hash - ` +
        `${usedHash} must be removed from heartbeat[]`;
    }
    if(newHeartbeat.length < prevHeartbeat.length) {
      return `entry ${i}: heartbeat key rotation must add a new heartbeat ` +
        `hash to replace the consumed one`;
    }
  }
  return null;
}

/**
 * Checks that the elapsed time between consecutive witnessed entries does not
 * exceed the heartbeatFrequency in effect before this entry.
 *
 * @param {object} options - Options.
 * @param {number} options.i - Log entry index.
 * @param {number|null} options.prevEntryWitnessTime - Latest witness ms for prev entry.
 * @param {number|null} options.entryWitnessTime - Latest witness ms for this entry.
 * @param {object|null} options.prevDidDocument - Document state before this entry.
 * @param {object|null} options.currentDidDocument - Document state after this entry.
 * @returns {string|null} Error message, or null if valid.
 */
function _checkHeartbeatFrequency(
  {i, prevEntryWitnessTime, entryWitnessTime, prevDidDocument,
    currentDidDocument}) {
  if(i === 0 || prevEntryWitnessTime === null || entryWitnessTime === null) {
    return null;
  }
  // Use the frequency from the previous document state so a tightened
  // heartbeatFrequency introduced by this entry is not applied retroactively
  // to the gap that preceded it.
  const heartbeatFrequency =
    (prevDidDocument ?? currentDidDocument)?.heartbeatFrequency ?? 'P1M';
  const freq = moment.duration(heartbeatFrequency);
  const elapsed = entryWitnessTime - prevEntryWitnessTime;
  if(elapsed > freq.asMilliseconds()) {
    const elapsedDuration = moment.duration(elapsed).humanize();
    return `entry ${i}: heartbeatFrequency violation - ` +
      `${elapsedDuration} elapsed since previous witnessed event ` +
      `exceeds ${heartbeatFrequency}`;
  }
  return null;
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
  {event, opProof, prevDidDocument}) {
  const vmRef = opProof.verificationMethod;

  // all operation proofs must use a did:key: heartbeat key
  if(!vmRef?.startsWith('did:key:')) {
    throw new Error(
      `operation proof verificationMethod must be a did:key: URI: ${vmRef}`);
  }

  // hash the did:key URI and verify it appears in the previous document's
  // heartbeat array; for the create event the call site passes the create
  // document itself as prevDidDocument so hbKey0 is found there
  const didKeyId = vmRef.split('#')[0];
  const hash = await hashDidKey(didKeyId);
  const heartbeat = prevDidDocument?.heartbeat ?? [];
  if(!heartbeat.includes(hash)) {
    throw new Error(
      `verification method not found in heartbeat: ${vmRef}`);
  }

  const publicKeyMultibase = didKeyId.replace('did:key:', '');
  const keyController = didKeyId;

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
 * Verifies a witness proof using the blind-witness signing scheme.
 * VerifyData = SHA256(JCS(proofOptions_without_proofValue)) || rawHash
 * where rawHash is the 32-byte SHA3-256 digest extracted from the
 * digestMultibase by stripping the 2-byte multihash header.
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
