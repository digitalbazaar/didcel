/**
 * @file DID document creation and management for the did:cel method.
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
const jdl = new JsonLdDocumentLoader();

/**
 * Creates a new did:cel DID document with a generated ECDSA key pair.
 * The DID identifier is derived from SHA3-256(JCS(initial document)) so
 * the identifier is self-certifying.
 *
 * @param {object} [options] - Configuration options.
 * @param {string} [options.curve='P-256'] - Elliptic curve for the key pair.
 * @param {string} [options.heartbeatFrequency='P1M'] - ISO 8601 duration.
 * @returns {Promise<object>} `{keyPair, heartbeatSecret, didDocument,
 *   cryptographicEventLog}`.
 */
export async function create(
  {curve = 'P-256', heartbeatFrequency = 'P1M'} = {}) {
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

  // derive the initial heartbeat key from a fresh 128-bit master secret
  const heartbeatSecret = crypto.randomBytes(16);
  const heartbeatKeyPair = await deriveHeartbeatKeyPair(heartbeatSecret, 0);
  const heartbeatPublicKey =
    await heartbeatKeyPair.export({publicKey: true, includeContext: false});

  // store only the hash of the did:key URI, not the key itself
  const heartbeatDidKey = `did:key:${heartbeatPublicKey.publicKeyMultibase}`;
  const heartbeatHash = await sha3256Multibase(heartbeatDidKey);

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

  // hash the draft document (before `id` is set) to produce the DID
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
 * Derives an ECDSA P-256 key pair from a heartbeat master secret and an
 * index using HKDF-SHA256. Index 0 is used at create time; index i signs
 * the i-th subsequent heartbeat event.
 *
 * @param {Buffer|Uint8Array} masterSecret - 16-byte master secret.
 * @param {number} index - Non-negative derivation index.
 * @returns {Promise<object>} EcdsaMultikey key pair.
 */
export async function deriveHeartbeatKeyPair(masterSecret, index) {
  // encode index as 4-byte big-endian info for HKDF domain separation
  const info = new Uint8Array(4);
  new DataView(info.buffer).setUint32(0, index, false);
  const salt = new TextEncoder().encode('did:cel:heartbeat-v1');
  const secretKey = hkdf(sha256, masterSecret, salt, info, 32);
  // derive the compressed P-256 public key via Node.js ECDH (no extra dep)
  const ecdhObj = crypto.createECDH('prime256v1');
  ecdhObj.setPrivateKey(secretKey);
  const publicKey = new Uint8Array(ecdhObj.getPublicKey(null, 'compressed'));
  const keyPair = await EcdsaMultikey.fromRaw({curve: 'P-256', secretKey, publicKey});
  // set id/controller so the key pair is self-describing as a did:key document
  const exported = await keyPair.export({publicKey: true, includeContext: false});
  const didKeyId = `did:key:${exported.publicKeyMultibase}`;
  keyPair.id = didKeyId;
  keyPair.controller = didKeyId;
  return keyPair;
}

/**
 * Generates a new key pair and adds it to the specified verification
 * relationship on a DID document. The proof is stripped and must be
 * regenerated via `createEvent` before the document is used.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.didDocument - The DID document to modify.
 * @param {string} options.verificationRelationship - Target relationship
 *   (e.g. `'authentication'`, `'keyAgreement'`).
 * @param {string} [options.curve='P-256'] - Elliptic curve for the new key.
 * @returns {Promise<object>} `{keyPair, didDocument}` (didDocument has no proof).
 */
export async function addVm({didDocument, verificationRelationship, curve}) {
  const newDidDocument = structuredClone(didDocument);
  const keyPair = await EcdsaMultikey.generate({curve: curve || 'P-256'});
  const publicKey =
    await keyPair.export({publicKey: true, includeContext: false});
  publicKey.id = '#' + publicKey.publicKeyMultibase;
  publicKey.controller = didDocument.id;

  if(!Array.isArray(didDocument[verificationRelationship])) {
    newDidDocument[verificationRelationship] = [];
  }
  newDidDocument[verificationRelationship].push(publicKey);
  delete newDidDocument.proof;

  _registerKeyWithDocumentLoader(publicKey, publicKey.controller);

  return {keyPair, didDocument: newDidDocument};
}

/**
 * Creates and signs an event. `previousEventHash` must be obtained via
 * `getPreviousEventHash()` and set before signing so the hash chain is
 * covered by the proof.
 *
 * @param {object} options - Configuration options.
 * @param {string} options.type - Event type: `'update'`, `'heartbeat'`, or
 *   `'deactivate'`.
 * @param {object} [options.data] - Operation data: full DID document for
 *   `update`, `{heartbeat:[…]}` for `heartbeat`, omit for `deactivate`.
 * @param {object} options.signingKeyPair - Heartbeat key pair to sign with.
 * @param {string} [options.previousEventHash] - Hash of the prior event.
 * @returns {Promise<object>} The signed event with proof attached.
 */
export async function createEvent(
  {type, data, signingKeyPair, previousEventHash}) {
  const operation = {type};
  if(data !== undefined) {
    operation.data = data;
  }
  const event = {operation};
  if(previousEventHash !== undefined) {
    event.previousEventHash = previousEventHash;
  }
  return _signEvent({event, signer: signingKeyPair.signer()});
}

/**
 * Sets `heartbeatFrequency` on a DID document. The proof is stripped and
 * must be regenerated via `createEvent` before the document is used.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.didDocument - The DID document to modify.
 * @param {string} options.heartbeatFrequency - ISO 8601 duration
 *   (e.g. `'P1D'`).
 * @returns {object} `{didDocument}` (no proof).
 */
export function setHeartbeatFrequency({didDocument, heartbeatFrequency}) {
  const newDidDocument = structuredClone(didDocument);
  newDidDocument.heartbeatFrequency = heartbeatFrequency;
  delete newDidDocument.proof;
  return {didDocument: newDidDocument};
}

/**
 * Registers a public key with the JSON-LD document loader under both its
 * fragment id (`#zAbc…`) and its controller-qualified id (`did:cel:z…#zAbc…`),
 * so jsigs can resolve the verification method during signing and verification.
 *
 * @param {object} publicKey - Exported key with `id` set to the fragment form.
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
