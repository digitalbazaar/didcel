/**
 * @fileoverview Certificate Event Log (CEL) management.
 * This module provides functions for creating, updating, and witnessing events
 * in a Certificate Event Log, which maintains a cryptographically verifiable
 * chain of events for DID document operations.
 */

import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {JsonLdDocumentLoader} from 'jsonld-document-loader';
import {base58btc} from 'multiformats/bases/base58';
import canonicalize from 'canonicalize';
import {createSignCryptosuite} from '@digitalbazaar/ecdsa-jcs-2019-cryptosuite';
import jsigs from 'jsonld-signatures';
import * as mfHasher from 'multiformats/hashes/hasher';
import {sha3_256} from '@noble/hashes/sha3.js';
import * as witnessService from './witness.js';

const {purposes: {AssertionProofPurpose}} = jsigs;
const jdl = new JsonLdDocumentLoader();

// default witness DIDs for validating CEL operations
let witnesses = [
  "did:web:red-witness.example",
  "did:web:green-witness.example",
  "did:web:blue-witness.example"
];

/**
 * Creates a new Certificate Event Log (CEL) with an initial 'create' event.
 * The log maintains a chain of events that document the history of DID operations.
 *
 * @param {Object} options - Configuration options.
 * @param {Object} options.event - The data for the create operation.
 * @param {Object} [options.options] - Optional configuration.
 * @returns {Object} A new CEL object with the structure:
 *   - log: Array containing the initial create event
 *
 * @example
 * const cel = create({
 *   event,
 * });
 */
export function create({event, options}) {
  // initialize the log with a create operation event
  let log = {
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
 * @param {Object} options - Configuration options.
 * @param {Object} options.cel - The Certificate Event Log containing events to
 *   witness.
 * @param {Object} [options.options] - Optional configuration (currently
 *   unused).
 * @returns {Promise<Array>} An array of proof objects, one from each witness.
 *
 * @example
 * const proofs = await witness({cel: myCel});
 *  // Returns array of proofs from red, green, and blue witnesses
 */
export async function witness({cel, options}) {
  const proofs = [];
  // get the most recent event from the log
  const event = cel.log[cel.log.length-1];

  // generate a cryptographic proof from each witness
  // each witness independently attests to the validity of the event
  for(let witness of witnesses) {
    const proof = await witnessService.generateProof(
      {data: event, options: {witness}});
    proofs.push(proof);
  }

  return proofs;
}

/**
 * Adds an update event to an existing CEL, creating a hash-linked chain of
 * events. The update event includes a hash of the previous event to ensure log
 * integrity.
 *
 * @param {Object} options - Configuration options.
 * @param {Object} options.cel - The Certificate Event Log to update.
 * @param {Object} options.event - The data for the update operation (typically
 *   an updated DID document).
 * @param {Object} [options.options] - Optional configuration (currently
 *   unused).
 * @returns {Promise<Object>} The updated CEL with the new event appended.
 *
 * @example
 * const updatedCel = await update({
 *   cel: existingCel,
 *   data: modifiedDidDocument
 * });
 */
export async function update({cel, event, options}) {
  // calculate the hash of the previous event to create a verifiable chain
  let previousEvent = undefined;
  if(cel.log.length > 0) {
    const lastEvent = cel.log[cel.log.length-1].event;
    const utf8Encoder = new TextEncoder();
    // canonicalize the event to ensure deterministic hashing
    const canonicalizedDidDocument = canonicalize(lastEvent);
    // create a SHA3-256 hasher with multiformats encoding
    const sha3256Hasher = mfHasher.from({
      name: 'sha3-256',
      code: 0x16,  // Multihash code for SHA3-256
      encode: input => sha3_256(input),
    });
    // compute the hash and encode it in base58btc
    const mfHash = await sha3256Hasher.digest(
      utf8Encoder.encode(canonicalizedDidDocument)).bytes;
    previousEvent = base58btc.encode(mfHash);
  }

  // append the new update event to the log, linked to the previous event
  event.previousEvent = previousEvent;
  cel.log.push({event});

  return cel;
}

export default {create, update, witness};
