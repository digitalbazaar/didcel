/**
 * @file DID CEL (Cryptographic Event Log) DID Document management.
 * This module provides functions for creating, updating, and managing DID
 * documents using the did:cel method with ECDSA Multikey and Data Integrity
 * Proofs.
 */

import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {assertValidDidDocument} from './validate.js';
import {create as celCreate} from './cel.js';
import {createSignCryptosuite} from '@digitalbazaar/ecdsa-jcs-2019-cryptosuite';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {hkdf} from '@noble/hashes/hkdf.js';
import {JsonLdDocumentLoader} from 'jsonld-document-loader';
import {sha256} from '@noble/hashes/sha2.js';
import {sha3256Multibase} from './utils.js';
import canonicalize from 'canonicalize';
import crypto from 'node:crypto';
import jsigs from 'jsonld-signatures';

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
 * @param {string} [options.heartbeatFrequency='P1M'] - ISO 8601 duration.
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
  {curve = 'P-256', heartbeatFrequency = 'P1M'} = {}) {
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
  publicKey.id = '#' + publicKey.publicKeyMultibase;

  // generate a 128-bit master secret for deterministic heartbeat key derivation
  const heartbeatSecret = crypto.randomBytes(16);
  const heartbeatKeyPair = await deriveHeartbeatKeyPair(heartbeatSecret, 0);
  const heartbeatPublicKey =
    await heartbeatKeyPair.export({publicKey: true, includeContext: false});

  // the heartbeat entry is a SHA3-256 multihash of the did:key URI, encoded as
  // base58btc multibase - the actual key is never stored in the document
  const heartbeatDidKey = `did:key:${heartbeatPublicKey.publicKeyMultibase}`;
  const heartbeatHash = await sha3256Multibase(heartbeatDidKey);

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

  // generate the did:cel identifier by hashing the canonicalized DID document,
  // then wire the controller into the document, key pair, and document loader
  const encodedHash = await sha3256Multibase(canonicalize(didDocument));
  const controller = 'did:cel:' + encodedHash;
  didDocument.id = controller;
  publicKey.controller = controller;
  keyPair.id = controller + publicKey.id;
  keyPair.controller = controller;
  _registerKeyWithDocumentLoader(publicKey, controller);

  assertValidDidDocument({didDocument});

  const event = {operation: {type: 'create', data: didDocument}};
  const signedEvent = await _signEvent({event, signer: heartbeatKeyPair.signer()});

  const cryptographicEventLog = celCreate({event: signedEvent});

  return {keyPair, heartbeatSecret, didDocument, cryptographicEventLog};
}

/**
 * Derives an ECDSA P-256 Multikey key pair from a heartbeat master secret and
 * an event index using HKDF-SHA256. The key at index 0 is placed in the DID
 * document at create time; index i is used to sign the i-th heartbeat event.
 *
 * @param {Buffer|Uint8Array} masterSecret - 16-byte heartbeat master secret.
 * @param {number} index - Non-negative integer event index.
 * @returns {Promise<object>} An EcdsaMultikey key pair.
 */
export async function deriveHeartbeatKeyPair(masterSecret, index) {
  // encode event index as 4-byte big-endian info for HKDF domain separation
  const info = new Uint8Array(4);
  new DataView(info.buffer).setUint32(0, index, false);
  const salt = new TextEncoder().encode('did:cel:heartbeat-v1');
  const secretKey = hkdf(sha256, masterSecret, salt, info, 32);
  // fromRaw() requires both secret and public key bytes; derive the compressed
  // P-256 public key point via Node.js built-in ECDH (no extra dependency)
  const ecdhObj = crypto.createECDH('prime256v1');
  ecdhObj.setPrivateKey(secretKey);
  const publicKey = new Uint8Array(ecdhObj.getPublicKey(null, 'compressed'));
  const keyPair = await EcdsaMultikey.fromRaw({curve: 'P-256', secretKey, publicKey});
  // set id/controller so the key pair can be passed directly to createEvent()
  const exported = await keyPair.export({publicKey: true, includeContext: false});
  const didKeyId = `did:key:${exported.publicKeyMultibase}`;
  keyPair.id = didKeyId;
  keyPair.controller = didKeyId;
  return keyPair;
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

  _registerKeyWithDocumentLoader(publicKey, publicKey.controller);

  return {keyPair, didDocument: newDidDocument};
}

/**
 * Creates a signed event given event data and an assertion method keypair.
 *
 * @param {object} options - Configuration options.
 * @param {string} options.type - The event type ('update', 'heartbeat', or
 *   'deactivate').
 * @param {object} [options.data] - DID document for update events; partial
 *   object with heartbeat field for heartbeat events; omit for deactivate.
 * @param {object} options.signingKeyPair - The heartbeat key pair to sign with.
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
 *   signingKeyPair: heartbeatKeyPair,
 *   previousEventHash
 * });
 */
export async function createEvent(
  {type, data, signingKeyPair, previousEventHash}) {
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
    await _signEvent({event, signer: signingKeyPair.signer()});

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
 * Registers a public key with the JSON-LD document loader under both its
 * short fragment id (e.g. '#zAbc…') and its full controller-qualified id
 * (e.g. 'did:cel:z…#zAbc…'), so jsigs can resolve the verification method
 * during proof creation and verification.
 *
 * @param {object} publicKey - Exported public key object with `id` set to the
 *   fragment form ('#<multibase>') and `controller` set to the DID.
 * @param {string} controller - The DID controller URI.
 */
function _registerKeyWithDocumentLoader(publicKey, controller) {
  jdl.addStatic(publicKey.id, publicKey);
  const fullId = controller + publicKey.id;
  jdl.addStatic(fullId, {
    ...publicKey, id: fullId,
    '@context': 'https://w3id.org/security/multikey/v1'
  });
}

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

export default {
  addVm, create, createEvent, deriveHeartbeatKeyPair, setHeartbeatFrequency
};
