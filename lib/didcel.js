/**
 * @file DID CEL (Cryptographic Event Log) DID Document management.
 * This module provides functions for creating, updating, and managing DID
 * documents using the did:cel method with ECDSA Multikey and Data Integrity
 * Proofs.
 */

import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {assertValidDidDocument} from './validate.js';
import canonicalize from 'canonicalize';
import {create as celCreate} from './cel.js';
import {createSignCryptosuite} from '@digitalbazaar/ecdsa-jcs-2019-cryptosuite';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import jsigs from 'jsonld-signatures';
import {JsonLdDocumentLoader} from 'jsonld-document-loader';
import {sha3256Multibase} from './utils.js';

const {purposes: {AssertionProofPurpose}} = jsigs;
// jSON-LD document loader for resolving contexts and verification methods
const jdl = new JsonLdDocumentLoader();

/**
 * Creates a new DID CEL document with a generated key pair and cryptographic
 * proof. The DID identifier is derived from the SHA3-256 hash of the
 * canonicalized DID document.
 *
 * @param {object} options - Configuration options.
 * @param {string} [options.curve='P-256'] - The elliptic curve to use for
 *   key generation (e.g., 'P-256', 'P-384').
 * @param {string} [options.heartbeatFrequency='P10Y'] - ISO 8601 duration.
 * @returns {Promise<object>} An object containing:
 *   - keyPair: The generated ECDSA Multikey key pair
 *   - heartbeatKeyPair: The generated ECDSA Multikey heartbeat key pair
 *   - didDocument: The signed DID document with a did:cel identifier.
 *   - cryptographicEventLog: The initial CEL with the create event.
 *
 * @example
 * const {keyPair, heartbeatKeyPair, didDocument, cryptographicEventLog} =
 *   await create({curve: 'P-256'});
 * console.log(didDocument.id);  // did:cel:z...
 */
export async function create(
  {curve = 'P-256', heartbeatFrequency = 'P10Y'} = {}) {
  // generate a new ECDSA key pair using the specified curve (defaults to P-256)
  let keyPair;
  try {
    keyPair = await EcdsaMultikey.generate({curve});
  } catch(e) {
    const err = new Error(`Key generation failed: ${e.message}`);
    err.name = 'KEY_GENERATION_ERROR';
    throw err;
  }
  const publicKey =
    await keyPair.export({publicKey: true, includeContext: false});
  // set the key id to the public key multibase encoding
  publicKey.id = '#' + publicKey.publicKeyMultibase;

  // generate a new heartbeat key pair using the specified curve
  let heartbeatKeyPair;
  try {
    heartbeatKeyPair = await EcdsaMultikey.generate({curve});
  } catch(e) {
    const err = new Error(`Heartbeat key generation failed: ${e.message}`);
    err.name = 'KEY_GENERATION_ERROR';
    throw err;
  }
  const heartbeatPublicKey =
    await heartbeatKeyPair.export({publicKey: true, includeContext: false});

  // register the assertion key with the document loader for proof verification
  jdl.addStatic(publicKey.id, publicKey);

  // the heartbeat entry is a SHA3-256 multihash of the did:key URI, encoded as
  // base58btc multibase - the actual key is never stored in the document
  const heartbeatDidKey = `did:key:${heartbeatPublicKey.publicKeyMultibase}`;
  const heartbeatHash = await hashDidKey(heartbeatDidKey);

  // create initial DID document structure with assertion method
  const didDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1.1',
      'https://w3id.org/didcel/v1'
    ],
    heartbeatFrequency,
    assertionMethod: [publicKey],
    heartbeat: [heartbeatHash],
    service: [
      {
        type: 'CelStorageService',
        serviceEndpoint: [
          'https://storage.gamma.example/v1',
          'https://2001:db8:85a3::8a2e:370:7334/v1',
          'https://celstorageiu7vnjjbwkhpilnemxj7ase3mhbshg7kx5tfydaniltxjqhy.onion/'
        ]
      }
    ]
  };

  // generate the did:cel identifier by hashing the canonicalized DID document
  const encodedHash = await sha3256Multibase(canonicalize(didDocument));
  const controller = 'did:cel:' + encodedHash;
  // update the DID document and assertion key with the generated identifier
  didDocument.id = controller;
  publicKey.controller = controller;

  // set the heartbeat key pair id to its did:key URI so callers can present it
  // as a verificationMethod when signing heartbeat operations
  heartbeatKeyPair.id = heartbeatDidKey;
  heartbeatKeyPair.controller = heartbeatDidKey;

  // set key id and controller so jsigs uses the correct verificationMethod
  keyPair.id = controller + publicKey.id;
  keyPair.controller = controller;

  // register the full VM id for document loader resolution during verification
  jdl.addStatic(keyPair.id, {
    ...publicKey, id: keyPair.id,
    '@context': 'https://w3id.org/security/multikey/v1'
  });

  assertValidDidDocument({didDocument});

  const event = {operation: {type: 'create', data: didDocument}};
  const signedEvent = await _signEvent({event, signer: keyPair.signer()});

  const cryptographicEventLog = celCreate({event: signedEvent});

  return {keyPair, heartbeatKeyPair, didDocument, cryptographicEventLog};
}

/**
 * Adds a new verification method (VM) to an existing DID document. Generates a
 * new key pair and adds it to the specified verification relationship. The
 * proof is removed and must be regenerated after this operation.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.didDocument - The DID document to modify.
 * @param {string} options.verificationRelationship - The verification
 *   relationship to add the key to (e.g., 'assertionMethod', 'authentication',
 *   'keyAgreement').
 * @param {string} [options.curve='P-256'] - The elliptic curve to use for key
 *   generation (e.g., 'P-256', 'P-384').
 * @returns {Promise<object>} An object containing:
 *   - keyPair: The newly generated ECDSA Multikey key pair
 *   - didDocument: The updated DID document (without proof).
 *
 * @example
 * const {keyPair, didDocument} = await addVm({
 *   didDocument: existingDoc,
 *   verificationRelationship: 'authentication',
 *   curve: 'P-256'
 * });
 */
export async function addVm({didDocument, verificationRelationship, curve}) {
  const newDidDocument = structuredClone(didDocument);
  // generate a new key pair for the verification method
  const keyPair =
    await EcdsaMultikey.generate({curve: curve || 'P-256'});
  const publicKey =
    await keyPair.export({publicKey: true, includeContext: false});
  publicKey.id = '#' + publicKey.publicKeyMultibase;
  publicKey.controller = didDocument.id;

  // add verification method to the specified verification relationship
  if(!Array.isArray(didDocument[verificationRelationship])) {
    newDidDocument[verificationRelationship] = [];
  }
  newDidDocument[verificationRelationship].push(publicKey);

  // remove old proof (must be regenerated via createEvent before addEvent)
  delete newDidDocument.proof;

  // register the new public key with the document loader (short and full ids)
  jdl.addStatic(publicKey.id, publicKey);
  const fullId = publicKey.controller + publicKey.id;
  jdl.addStatic(fullId, {
    ...publicKey, id: fullId,
    '@context': 'https://w3id.org/security/multikey/v1'
  });

  return {keyPair, didDocument: newDidDocument};
}

/**
 * Creates a signed event given event data and an assertion method keypair.
 *
 * @param {object} options - Configuration options.
 * @param {string} options.type - The event type ('update', 'heartbeat', or
 *   'deactivate').
 * @param {object} [options.data] - DID document for update events; omit
 *   (or pass undefined) for heartbeat and deactivate events.
 * @param {object} options.assertionMethod - The key pair to use for signing.
 *   Must have a signer() method.
 * @param {string} [options.previousEventHash] - Base58btc SHA3-256 hash of
 *   the previous event, obtained from getPreviousEventHash(). Required for
 *   all non-create events so the hash is covered by the operation proof.
 * @returns {Promise<object>} An object containing:
 *   - event: The signed event object with proof attached.
 *
 * @example
 * const previousEventHash =
 *   await getPreviousEventHash({cel: cryptographicEventLog});
 * const {event} = await createEvent({
 *   type: 'update',
 *   data: updatedDidDocument,
 *   assertionMethod: keyPair,
 *   previousEventHash
 * });
 */
export async function createEvent(
  {type, data, assertionMethod, previousEventHash}) {
  const operation = {type};
  if(data !== undefined) {
    operation.data = data;
  }
  const event = {operation};
  // set previousEventHash before signing so it is covered by the proof
  if(previousEventHash !== undefined) {
    event.previousEventHash = previousEventHash;
  }
  const signedEvent =
    await _signEvent({event, signer: assertionMethod.signer()});

  return {event: signedEvent};
}

/**
 * Sets the heartbeatFrequency on an existing DID document. The proof is
 * removed and must be regenerated with createEvent before adding to the CEL.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.didDocument - The DID document to modify.
 * @param {string} options.heartbeatFrequency - ISO 8601 duration string
 *   (e.g. 'P3M', 'P1Y', 'P1D').
 * @returns {object} An object containing the updated |didDocument| (no proof).
 */
export function setHeartbeatFrequency({didDocument, heartbeatFrequency}) {
  const newDidDocument = structuredClone(didDocument);
  newDidDocument.heartbeatFrequency = heartbeatFrequency;
  delete newDidDocument.proof;
  return {didDocument: newDidDocument};
}

/**
 * Computes the base58btc-encoded SHA3-256 multihash of a did:key URI string.
 * This is the value stored in the `heartbeat` array of a DID document.
 *
 * @param {string} didKey - The did:key URI to hash (e.g. 'did:key:z...').
 * @returns {Promise<string>} Base58btc multibase-encoded SHA3-256 multihash.
 */
export async function hashDidKey(didKey) {
  return sha3256Multibase(didKey);
}

/**
 * Signs an event object using ecdsa-jcs-2019 and returns the signed event.
 *
 * @param {object} options - Options.
 * @param {object} options.event - The event object to sign.
 * @param {object} options.signer - The signer from a key pair's .signer() call.
 * @returns {Promise<object>} The signed event with proof attached.
 */
async function _signEvent({event, signer}) {
  const suite = new DataIntegrityProof({
    signer, cryptosuite: createSignCryptosuite()
  });
  return jsigs.sign(event, {
    suite,
    purpose: new AssertionProofPurpose(),
    documentLoader: jdl.build()
  });
}

export default {create, addVm, createEvent, setHeartbeatFrequency, hashDidKey};
