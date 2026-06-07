/**
 * @file Cryptographic Event Log (CEL) management.
 * This module provides functions for creating, updating, and witnessing events
 * in a Cryptographic Event Log, which maintains a cryptographically verifiable
 * chain of events for DID document operations.
 */

import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as mfHasher from 'multiformats/hashes/hasher';
import * as witnessService from './witness.js';
import {hashDidKey} from './didcel.js';
import {base58btc} from 'multiformats/bases/base58';
import {decode as base58Decode} from 'base58-universal';
import canonicalize from 'canonicalize';
import crypto from 'node:crypto';
import moment from 'moment';
import {readFileSync} from 'node:fs';
import {sha3_256} from '@noble/hashes/sha3.js';

// SHA3-256 multihash header: function code 0x16, digest size 32 (0x20)
const SHA3_256_HEADER = new Uint8Array([0x16, 0x20]);

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
  const logEntry = cel.log[cel.log.length - 1];

  // canonicalize and SHA3-256 hash the bare event object (not the log entry
  // wrapper) to produce the digestMultibase, per the spec witness algorithm
  const utf8Encoder = new TextEncoder();
  const canonicalized = canonicalize(logEntry.event);
  const rawHash = sha3_256(utf8Encoder.encode(canonicalized));

  // build SHA3-256 multihash and encode as base58btc with 'z' multibase prefix
  const mhBytes = new Uint8Array(SHA3_256_HEADER.length + rawHash.length);
  mhBytes.set(SHA3_256_HEADER, 0);
  mhBytes.set(rawHash, SHA3_256_HEADER.length);
  const digestMultibase = base58btc.encode(mhBytes);

  const witnessUrls = witnesses;
  if(!Array.isArray(witnessUrls) || witnessUrls.length === 0) {
    throw new Error('No witnesses provided.');
  }

  const proofs = await Promise.all(witnessUrls.map(
    witnessUrl => witnessService.witness({digestMultibase, witnessUrl})));

  logEntry.proof = proofs;

  return logEntry.proof;
}

export async function getPreviousEventHash({cel}) {
  // calculate the hash of the previous event to create a verifiable chain
  let previousEventHash = undefined;
  if(cel.log.length > 0) {
    const lastEvent = cel.log[cel.log.length - 1].event;
    const utf8Encoder = new TextEncoder();
    // canonicalize the event to ensure deterministic hashing
    const canonicalizedDidDocument = canonicalize(lastEvent);
    // create a SHA3-256 hasher with multiformats encoding
    const sha3256Hasher = mfHasher.from({
      name: 'sha3-256',
      code: 0x16, // Multihash code for SHA3-256
      encode: input => sha3_256(input),
    });
    // compute the hash and encode it in base58btc
    const mfHash = await sha3256Hasher.digest(
      utf8Encoder.encode(canonicalizedDidDocument)).bytes;
    previousEventHash = base58btc.encode(mfHash);
  }

  return previousEventHash;
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
  // previousEventHash must already be set on the event (and covered by the
  // operation proof) before calling this function
  cel.log.push({event});

  return cel;
}

/**
 * Loads and fully validates a Cryptographic Event Log from a file. Checks:
 * - Hash chain integrity (previousEventHash on each non-create entry)
 * - Operation proof signatures (ecdsa-jcs-2019 via manual JCS verification)
 * - Witness proof signatures (blind-witness manual JCS verification)
 * - Timestamp deviation between operation proof and witness proofs (≤ 5 min).
 *
 * @param {object} options - Configuration options.
 * @param {string} options.filename - Path to the .cel file to load.
 * @returns {Promise<object>} An object with:
 *   - cel: The parsed CEL object.
 *   - errors: Array of error strings (empty if valid).
 *   - valid: Boolean, true if no errors.
 *   - didDocument: The most recent DID document state (or null).
 */
export async function load({filename}) {
  const cel = JSON.parse(readFileSync(filename, 'utf8'));
  const errors = [];
  let currentDidDocument = null;
  // latest witness timestamp for the previous log entry, used for heartbeat
  // frequency checks at each subsequent entry boundary
  let prevEntryWitnessTime = null;

  for(let i = 0; i < cel.log.length; i++) {
    const logEntry = cel.log[i];
    const event = logEntry.event;
    const opProof = event.proof;
    const witnessProofs = logEntry.proof ?? [];

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

    // 2. Verify the operation proof.
    // assertionMethod keys are looked up in currentDidDocument (the new state
    // introduced by this entry). Recovery keys must be looked up in
    // prevDidDocument — the state that was in effect before this update, where
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

    // 3. Verify each witness proof and check timestamp deviation
    const opTime = opProof?.created ?
      new Date(opProof.created).getTime() : null;
    let entryWitnessTime = null;
    for(let j = 0; j < witnessProofs.length; j++) {
      const witnessProof = witnessProofs[j];

      try {
        const verified = await _verifyWitnessProof({logEntry, witnessProof});
        if(!verified) {
          errors.push(`entry ${i} witness ${j}: invalid signature`);
        }
      } catch(e) {
        errors.push(`entry ${i} witness ${j}: error: ${e.message}`);
      }

      // 4. Check timestamp deviation ≤ 5 minutes
      if(opTime !== null && witnessProof.created) {
        const wTime = new Date(witnessProof.created).getTime();
        const diffMinutes = Math.abs(opTime - wTime) / 60000;
        if(diffMinutes > 5) {
          errors.push(
            `entry ${i} witness ${j}: timestamp deviation ` +
            `${diffMinutes.toFixed(1)}min exceeds 5min limit`);
        }
        // track the latest witness timestamp for this entry
        if(entryWitnessTime === null || wTime > entryWitnessTime) {
          entryWitnessTime = wTime;
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
              `entry ${i}: recovery key used without rotating its hash — ` +
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
    // This check applies to all event types including deactivate — a DID is
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
          `entry ${i}: heartbeatFrequency violation — ` +
          `${elapsedDuration} elapsed since previous witnessed event ` +
          `exceeds ${heartbeatFrequency}`);
      }
    }

    // advance the previous entry witness time for the next iteration
    if(entryWitnessTime !== null) {
      prevEntryWitnessTime = entryWitnessTime;
    }
  }

  return {
    cel, errors, valid: errors.length === 0, didDocument: currentDidDocument
  };
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
    // recovery[] of the *previous* document — the update will rotate it out,
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
  // (same as what was sent to the witness service, per the spec witness algorithm)
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

export default {addEvent, create, load, witness};
