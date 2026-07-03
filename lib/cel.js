/**
 * @file Cryptographic Event Log (CEL) read, write, and validation.
 */

import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as witnessService from './witness.js';
import {gunzipSync, gzipSync} from 'node:zlib';
import {readFileSync, writeFileSync} from 'node:fs';
import {sha3256Multibase, VERIFICATION_RELATIONSHIPS} from './utils.js';
import {assertValidCel} from './validate.js';
import {decode as base58Decode} from 'base58-universal';
import canonicalize from 'canonicalize';
import crypto from 'node:crypto';
import moment from 'moment';
import {sha3_256} from '@noble/hashes/sha3.js';

/**
 * Creates a new CEL containing a single create event.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.event - The signed create event.
 * @returns {object} CEL object: `{log: [{event}]}`.
 */
export function create({event}) {
  return {log: [{event}]};
}

/**
 * Sends the last event in a CEL to each witness and attaches their proofs.
 * The event is hashed (SHA3-256 multihash) and the digest is sent to each
 * witness URL; each witness returns a DataIntegrityProof.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.cel - The CEL whose last event will be witnessed.
 * @param {Array<string>} options.witnesses - Witness service URLs.
 * @param {boolean} [options.allowSelfSigned=false] - Passed through to the
 *   HTTP witness client; see `witnessService.witness()`.
 * @returns {Promise<Array>} The proof array attached to the last log entry.
 */
export async function witness({cel, witnesses, allowSelfSigned}) {
  if(!cel.log || cel.log.length === 0) {
    const err = new Error(
      'Cannot witness an empty CEL log - use cel.create() first');
    err.name = 'MALFORMED_CEL_ERROR';
    throw err;
  }
  if(!Array.isArray(witnesses) || witnesses.length === 0) {
    throw new Error('No witnesses provided.');
  }

  // hash the last log entry
  const logEntry = cel.log[cel.log.length - 1];
  const digestMultibase = sha3256Multibase(canonicalize(logEntry.event));

  let proofs;
  try {
    proofs = await Promise.all(witnesses.map(
      witnessUrl => witnessService.witness(
        {digestMultibase, witnessUrl, allowSelfSigned})));
  } catch(e) {
    const err = new Error(`Witnessing failed: ${e.message}`);
    err.name = 'WITNESSING_ERROR';
    throw err;
  }

  logEntry.proof = proofs;
  return logEntry.proof;
}

/**
 * Returns the SHA3-256 multibase hash of the last event in a CEL.
 * Callers include this value as `previousEventHash` on the next event
 * before signing, so the hash chain is covered by the operation proof.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.cel - The CEL.
 * @returns {string|undefined} Multibase hash, or undefined if empty.
 */
export function getPreviousEventHash({cel}) {
  if(cel.log.length === 0) {
    return undefined;
  }
  const lastEvent = cel.log[cel.log.length - 1].event;
  return sha3256Multibase(canonicalize(lastEvent));
}

/**
 * Appends a signed event to a CEL, extending the hash-linked chain.
 * `previousEventHash` must already be set on the event and covered by its
 * proof before calling this function.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.cel - The CEL to append to.
 * @param {object} options.event - The signed event to append.
 * @returns {Promise<object>} The updated CEL.
 */
export async function addEvent({cel, event}) {
  if(!cel.log || cel.log.length === 0) {
    const err = new Error(
      'Cannot add event to an empty CEL log - use cel.create() first');
    err.name = 'MALFORMED_CEL_ERROR';
    throw err;
  }
  const isDeactivated = cel.log.some(
    entry => entry.event?.operation?.type === 'deactivate');
  if(isDeactivated) {
    const err = new Error(
      'Cannot add event to a deactivated CEL - deactivation is final');
    err.name = 'MALFORMED_CEL_ERROR';
    throw err;
  }
  cel.log.push({event});
  assertValidCel({cel});
  return cel;
}

/**
 * Reads and fully validates a CEL. Returns `{cel, errors, valid, didDocument}`.
 *
 * Checks performed for each log entry, in order:
 *   1. Structure — JSON Schema via assertValidCel().
 *   2. Self-certifying DID — `did:cel:` must equal SHA3-256(JCS(initial doc)).
 *   3. Hash chain — `previousEventHash` must match the prior event's digest.
 *   4. Operation proof — ecdsa-jcs-2019, keys from the *prior* DID document.
 *   5. Heartbeat rotation — signing key hash must be swapped out after use.
 *   6. Witness proofs — signature + ≤5 min clock deviation per recognized
 *      witness.
 *   7. Heartbeat frequency — gap between consecutive witnessed entries.
 *
 * Witness errors are deferred one iteration so that a backdated timestamp
 * triggers a heartbeatFrequency violation on the next entry (the root cause)
 * rather than surfacing as a signature error on the backdated entry.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.cel - The parsed CEL.
 * @param {Array<object>} [options.recognizedWitnesses=[]] - Recognized witness
 *   entries: `{id, validFrom, validUntil}`. Proofs from unknown witnesses or
 *   outside the validity window are ignored.
 * @param {string|null} [options.versionTime=null] - XMLDateTimeStamp. When set,
 *   entries whose earliest recognized witness timestamp exceeds this value are
 *   skipped, enabling historical DID document resolution.
 * @returns {Promise<object>} `{cel, errors, valid, didDocument}`.
 */
export async function read(
  {cel, recognizedWitnesses = [], versionTime = null}) {
  try {
    assertValidCel({cel});
  } catch(e) {
    return {cel, errors: [e.message], valid: false, didDocument: null};
  }

  if(cel.log.length === 0) {
    return {cel, errors: ['CEL is empty'], valid: false, didDocument: null};
  }

  const idErr = _verifySelfCertifyingId({firstEvent: cel.log[0].event});
  if(idErr) {
    return {cel, errors: [idErr], valid: false, didDocument: null};
  }

  let currentDidDocument = null;
  let prevEntryWitnessTime = null; // latest witness ms from the prior entry
  let deactivated = false;
  // Witness errors are held here for one iteration. If the next entry's
  // heartbeatFrequency check fires, it supersedes them as the root cause.
  let pendingWitnessErrors = null;

  for(let i = 0; i < cel.log.length; i++) {
    const logEntry = cel.log[i];
    const event = logEntry.event;
    const opProof = event.proof;
    const witnessProofs = logEntry.proof ?? [];

    if(deactivated) {
      return {
        cel,
        errors: [`entry ${i}: operation after deactivation is not permitted`],
        valid: false,
        didDocument: null
      };
    }

    const recognizedWitnessProofs = witnessProofs.filter(
      wp => _isRecognizedWitnessProof({wp, recognizedWitnesses}));

    // versionTime cutoff — must run before any state mutation so a skipped
    // entry can never contaminate the verified document returned to the caller
    if(versionTime !== null && recognizedWitnessProofs.length > 0) {
      const versionTimeMs = new Date(versionTime).getTime();
      const earliestWitnessTime = Math.min(
        ...recognizedWitnessProofs.map(wp => new Date(wp.created).getTime()));
      if(earliestWitnessTime > versionTimeMs) {
        break;
      }
    }

    if(i > 0) {
      const chainErr = _verifyHashChain({cel, i, event});
      if(chainErr) {
        return {cel, errors: [chainErr], valid: false, didDocument: null};
      }
    }

    // Snapshot prevDidDocument before advancing — the heartbeatFrequency check
    // needs the frequency in effect for the gap leading into this entry, not
    // any new value this entry's update might introduce.
    const prevDidDocument = currentDidDocument;
    currentDidDocument = _advanceDidDocument({currentDidDocument, event});

    if(event.operation?.type === 'deactivate') {
      deactivated = true;
    }

    // Look up keys in the *prior* document to prevent circular
    // key-introduction: an attacker must not add a key via an update and
    // simultaneously use that key to sign the update. The create event
    // (i === 0) has no prior state; its integrity is pinned by the ID.
    const verifyDidDocument = i === 0 ? currentDidDocument : prevDidDocument;
    const opProofErr = await _verifyOperationProofEntry(
      {i, event, opProof, verifyDidDocument, prevDidDocument});
    if(opProofErr) {
      return {cel, errors: [opProofErr], valid: false, didDocument: null};
    }

    const rotationErr = _checkHeartbeatRotation(
      {i, event, opProof, prevDidDocument, currentDidDocument});
    if(rotationErr) {
      return {cel, errors: [rotationErr], valid: false, didDocument: null};
    }

    const {errors: witnessErrors, entryWitnessTime} =
      await _verifyWitnessProofsEntry(
        {i, logEntry, recognizedWitnessProofs, opProof});

    // A frequency violation supersedes pending witness errors from the prior
    // entry — a backdated timestamp is the root cause of both.
    const freqErr = _checkHeartbeatFrequency(
      {i, prevEntryWitnessTime, entryWitnessTime, prevDidDocument,
        currentDidDocument});
    if(freqErr) {
      return {cel, errors: [freqErr], valid: false, didDocument: null};
    }

    if(pendingWitnessErrors) {
      return {
        cel, errors: pendingWitnessErrors, valid: false, didDocument: null};
    }

    if(entryWitnessTime !== null) {
      prevEntryWitnessTime = entryWitnessTime;
    }
    pendingWitnessErrors = witnessErrors.length > 0 ? witnessErrors : null;
  }

  if(pendingWitnessErrors) {
    return {cel, errors: pendingWitnessErrors, valid: false, didDocument: null};
  }

  return {cel, errors: [], valid: true, didDocument: currentDidDocument};
}

/**
 * Checks that the DID in the first event equals
 * `did:cel:` + SHA3-256(JCS(doc without `id` and VM `controller` fields)).
 * Those fields are stripped to reconstruct the pre-hash document state.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.firstEvent - The first log entry's event.
 * @returns {string|null} Error message, or null if valid.
 */
function _verifySelfCertifyingId({firstEvent}) {
  const firstDidDocument = structuredClone(firstEvent?.operation?.data ?? {});
  delete firstDidDocument.id;
  for(const rel of VERIFICATION_RELATIONSHIPS) {
    if(Array.isArray(firstDidDocument[rel])) {
      for(const vm of firstDidDocument[rel]) {
        if(typeof vm === 'object') {
          delete vm.controller;
        }
      }
    }
  }
  const expectedId =
    'did:cel:' + sha3256Multibase(canonicalize(firstDidDocument));
  const claimedId = firstEvent?.operation?.data?.id;
  if(claimedId !== expectedId) {
    return `DID identifier mismatch: claimed "${claimedId}", ` +
      `expected "${expectedId}"`;
  }
  return null;
}

/**
 * Checks that `event.previousEventHash` equals the SHA3-256 hash of the
 * prior event.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.cel - The full CEL.
 * @param {number} options.i - Current entry index (must be > 0).
 * @param {object} options.event - The current event.
 * @returns {string|null} Error message, or null if valid.
 */
function _verifyHashChain({cel, i, event}) {
  const computed = sha3256Multibase(canonicalize(cel.log[i - 1].event));
  if(computed !== event.previousEventHash) {
    return `entry ${i}: previousEventHash mismatch ` +
      `(expected ${computed}, got ${event.previousEventHash})`;
  }
  return null;
}

/**
 * Returns the DID document state after applying an event's operation.
 * Heartbeat merges only the `heartbeat` array into the existing document;
 * all other operations replace the document wholesale.
 *
 * @param {object} options - Configuration options.
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
 * Keys are looked up in `verifyDidDocument` (the previously verified state)
 * to prevent circular key-introduction attacks.
 *
 * @param {object} options - Configuration options.
 * @param {number} options.i - Log entry index.
 * @param {object} options.event - The event object.
 * @param {object} options.opProof - The operation proof (may be undefined).
 * @param {object} options.verifyDidDocument - Document to look up signing keys
 *   in.
 * @param {object|null} options.prevDidDocument - Document state before this
 *   entry.
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
 * Verifies all recognized witness proofs for a single log entry.
 * Also checks that each witness timestamp is within 5 min of the operation
 * proof timestamp. Returns all errors and the latest witness timestamp seen.
 *
 * @param {object} options - Configuration options.
 * @param {number} options.i - Log entry index.
 * @param {object} options.logEntry - The full log entry `{event, proof[]}`.
 * @param {Array} options.recognizedWitnessProofs - Pre-filtered recognized
 *   proofs.
 * @param {object} options.opProof - The operation proof (for timestamp check).
 * @returns {Promise<{errors: string[], entryWitnessTime: number|null}>}
 *   All errors found and the latest witness timestamp seen.
 */
async function _verifyWitnessProofsEntry(
  {i, logEntry, recognizedWitnessProofs, opProof}) {
  const errors = [];
  const opTime = opProof?.created ?
    new Date(opProof.created).getTime() : null;
  let entryWitnessTime = null;

  for(let j = 0; j < recognizedWitnessProofs.length; j++) {
    const witnessProof = recognizedWitnessProofs[j];

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
 * Checks that the heartbeat key used to sign this entry has been rotated:
 * its hash must be removed from `heartbeat[]` and a new one added.
 * Skipped for the create event (no predecessor) and deactivate (terminal).
 *
 * @param {object} options - Configuration options.
 * @param {number} options.i - Log entry index.
 * @param {object} options.event - The event object.
 * @param {object} options.opProof - The operation proof.
 * @param {object|null} options.prevDidDocument - Document state before this
 *   entry.
 * @param {object|null} options.currentDidDocument - Document state after this
 *   entry.
 * @returns {string|null} Error message, or null if valid.
 */
function _checkHeartbeatRotation(
  {i, event, opProof, prevDidDocument, currentDidDocument}) {
  if(!opProof || !currentDidDocument || i === 0 ||
      event.operation?.type === 'deactivate') {
    return null;
  }
  const vmRef = opProof.verificationMethod;
  if(!vmRef?.startsWith('did:key:')) {
    return null;
  }
  const didKeyId = vmRef.split('#')[0];
  const usedHash = sha3256Multibase(didKeyId);
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
 * exceed the `heartbeatFrequency` in effect for the gap. Uses the frequency
 * from `prevDidDocument` so a tightened value introduced by this entry does
 * not apply retroactively to the gap that preceded it.
 *
 * @param {object} options - Configuration options.
 * @param {number} options.i - Log entry index.
 * @param {number|null} options.prevEntryWitnessTime - Latest witness ms from
 *   the prior entry.
 * @param {number|null} options.entryWitnessTime - Latest witness ms for this
 *   entry.
 * @param {object|null} options.prevDidDocument - Document state before this
 *   entry.
 * @param {object|null} options.currentDidDocument - Document state after this
 *   entry.
 * @returns {string|null} Error message, or null if valid.
 */
function _checkHeartbeatFrequency(
  {i, prevEntryWitnessTime, entryWitnessTime, prevDidDocument,
    currentDidDocument}) {
  if(i === 0 || prevEntryWitnessTime === null || entryWitnessTime === null) {
    return null;
  }
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
 * Returns true if `wp` was issued by a recognized witness and its `created`
 * timestamp falls within that witness's `validFrom`/`validUntil` window.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.wp - The witness proof to evaluate.
 * @param {Array<object>} options.recognizedWitnesses - Recognized witness
 *   entries.
 * @returns {boolean} True if the proof is from a recognized witness in its
 *   validity window.
 */
function _isRecognizedWitnessProof({wp, recognizedWitnesses}) {
  const vmDid = wp.verificationMethod?.split('#')[0];
  const entry = recognizedWitnesses.find(tw => tw.id === vmDid);
  if(!entry) {
    return false;
  }
  if(!wp.created) {
    return false;
  }
  const created = new Date(wp.created);
  if(entry.validFrom && created < new Date(entry.validFrom)) {
    return false;
  }
  if(entry.validUntil && created > new Date(entry.validUntil)) {
    return false;
  }
  return true;
}

/**
 * Returns SHA-256(JCS(proof without `proofValue`)) as a Uint8Array.
 * This is the first half of `verifyData` for both ecdsa-jcs-2019 schemes.
 *
 * @param {object} proof - The proof object.
 * @returns {Uint8Array} SHA-256 digest of the canonicalized proof options.
 */
function _hashProofOptions(proof) {
  const proofOptions = {...proof};
  delete proofOptions.proofValue;
  return new Uint8Array(
    crypto.createHash('sha256').update(canonicalize(proofOptions)).digest());
}

/**
 * Builds an EcdsaMultikey verifier from a `did:key:` verification method URI.
 *
 * @param {string} vmId - Full verificationMethod URI (`did:key:z…#z…`).
 * @returns {Promise<object>} EcdsaMultikey verifier.
 */
async function _buildEcdsaVerifier(vmId) {
  const didKeyId = vmId.split('#')[0];
  const publicKeyMultibase = didKeyId.replace('did:key:', '');
  const keyPair = await EcdsaMultikey.from({
    type: 'Multikey',
    id: vmId,
    controller: didKeyId,
    publicKeyMultibase
  });
  return keyPair.verifier();
}

/**
 * Verifies an operation proof (ecdsa-jcs-2019).
 * VerifyData = SHA256(JCS(proofOptions)) || SHA256(JCS(event without proof)).
 * The signing key must appear in `prevDidDocument.heartbeat[]`.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.event - The event object.
 * @param {object} options.opProof - The operation proof.
 * @param {object} options.prevDidDocument - Document used for key lookup.
 * @returns {Promise<boolean>} True if the proof is valid.
 */
async function _verifyOperationProof({event, opProof, prevDidDocument}) {
  const vmRef = opProof.verificationMethod;
  if(!vmRef?.startsWith('did:key:')) {
    throw new Error(
      `operation proof verificationMethod must be a did:key: URI: ${vmRef}`);
  }

  // signing key hash must appear in heartbeat[]; for the create event the
  // caller passes the create document itself, so hbKey0 is found there
  const didKeyId = vmRef.split('#')[0];
  const hash = sha3256Multibase(didKeyId);
  const heartbeat = prevDidDocument?.heartbeat ?? [];
  if(!heartbeat.includes(hash)) {
    throw new Error(`verification method not found in heartbeat: ${vmRef}`);
  }

  // previousEventHash is set before signing, so it is covered by the proof
  const doc = {...event};
  delete doc.proof;
  const proofHash = _hashProofOptions(opProof);
  const docHash = new Uint8Array(
    crypto.createHash('sha256').update(canonicalize(doc)).digest());

  const verifyData = new Uint8Array(proofHash.length + docHash.length);
  verifyData.set(proofHash, 0);
  verifyData.set(docHash, proofHash.length);

  const verifier = await _buildEcdsaVerifier(vmRef);
  const sigBytes = base58Decode(opProof.proofValue.slice(1));
  return verifier.verify({data: verifyData, signature: sigBytes});
}

/**
 * Verifies a witness proof (blind-witness ecdsa-jcs-2019).
 * VerifyData = SHA256(JCS(proofOptions)) || SHA3-256(JCS(event)).
 * The raw SHA3-256 digest (not a multihash) is used because the witness
 * receives and signs the digest directly without multihash framing.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.logEntry - The full log entry `{event, proof[]}`.
 * @param {object} options.witnessProof - The witness proof to verify.
 * @returns {Promise<boolean>} True if the proof is valid.
 */
async function _verifyWitnessProof({logEntry, witnessProof}) {
  if(witnessProof.proofPurpose !== 'assertionMethod') {
    throw new Error(
      `witness proof proofPurpose must be "assertionMethod", ` +
      `got "${witnessProof.proofPurpose}"`);
  }

  // rawHash matches the digest sent to the witness service
  const rawHash = sha3_256(
    new TextEncoder().encode(canonicalize(logEntry.event)));

  const proofHash = _hashProofOptions(witnessProof);
  const verifyData = new Uint8Array(proofHash.length + rawHash.length);
  verifyData.set(proofHash, 0);
  verifyData.set(rawHash, proofHash.length);

  const verifier = await _buildEcdsaVerifier(witnessProof.verificationMethod);
  const sigBytes = base58Decode(witnessProof.proofValue.slice(1));
  return verifier.verify({data: verifyData, signature: sigBytes});
}

/**
 * Loads and validates a gzip-compressed CEL from disk. See `read()`.
 *
 * @param {object} options - Configuration options.
 * @param {string} options.filename - Path to the `.cel` file.
 * @param {Array<object>} [options.recognizedWitnesses=[]] - See `read()`.
 * @param {string|null} [options.versionTime=null] - See `read()`.
 * @returns {Promise<object>} See `read()`.
 */
export async function loadFromFile(
  {filename, recognizedWitnesses = [], versionTime = null}) {
  const compressed = readFileSync(filename);
  const cel = JSON.parse(gunzipSync(compressed).toString('utf8'));
  return read({cel, recognizedWitnesses, versionTime});
}

/**
 * Serializes a CEL to gzip-compressed JSON and writes it to disk.
 *
 * @param {object} options - Configuration options.
 * @param {string} options.filename - Destination path.
 * @param {object} options.cel - The CEL to save.
 */
export function saveToFile({filename, cel}) {
  const compressed = gzipSync(Buffer.from(JSON.stringify(cel), 'utf8'));
  writeFileSync(filename, compressed);
}

export default {addEvent, create, loadFromFile, read, saveToFile, witness};
