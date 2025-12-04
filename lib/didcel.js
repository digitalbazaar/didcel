/**
 * @fileoverview DID CEL (Certificate Event Log) DID Document management.
 * This module provides functions for creating, updating, and managing DID
 * documents using the did:cel method with ECDSA Multikey and Data Integrity
 * Proofs.
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

const {purposes: {AssertionProofPurpose}} = jsigs;
// jSON-LD document loader for resolving contexts and verification methods
const jdl = new JsonLdDocumentLoader();

/**
 * Creates a new DID CEL document with a generated key pair and cryptographic
 * proof. The DID identifier is derived from the SHA3-256 hash of the
 * canonicalized DID document.
 *
 * @param {Object} options - Configuration options.
 * @param {Object} [options.options] - Optional configuration.
 * @param {string} [options.options.curve='P-256'] - The elliptic curve to use
 *   for key generation (e.g., 'P-256', 'P-384').
 * @returns {Promise<Object>} An object containing:
 *   - keyPair: The generated ECDSA Multikey key pair
 *   - didDocument: The signed DID document with a did:cel identifier
 *
 * @example
 * const {keyPair, didDocument} = await create({options: {curve: 'P-256'}});
 * console.log(didDocument.id);  // did:cel:z...
 */
export async function create({options}) {
  // generate a new ECDSA key pair using the specified curve (defaults to P-256)
  const keyPair =
    await EcdsaMultikey.generate({curve: options?.curve || 'P-256'});
  const publicKey =
    await keyPair.export({publicKey: true, includeContext: false});
  // set the key id to the public key multibase encoding
  publicKey.id = '#' + publicKey.publicKeyMultibase;

  // register the public key with the document loader for proof verification
  jdl.addStatic(publicKey.id, publicKey);

  // create initial DID document structure with assertion method
  let didDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1.1',
      'https://w3id.org/didcel/v1'
    ],
    assertionMethod: [publicKey],
    service: {
      type: 'CelStorageService',
      serviceEndpoint: [
        'https://storage.gamma.example/v1',
        'https://2001:db8:85a3::8a2e:370:7334/v1',
        'https://celstorageiu7vnjjbwkhpilnemxj7ase3mhbshg7kx5tfydaniltxjqhy.onion/',
      ]
    }
  }

  // generate the did:cel identifier by hashing the canonicalized DID document
  const utf8Encoder = new TextEncoder();
  const canonicalizedDidDocument = canonicalize(didDocument);
  const sha3256Hasher = mfHasher.from({
    name: 'sha3-256',
    code: 0x16,  // Multihash code for SHA3-256
    encode: input => sha3_256(input),
  });
  const mfHash = await sha3256Hasher.digest(
    utf8Encoder.encode(canonicalizedDidDocument)).bytes;
  const encodedHash = base58btc.encode(mfHash);
  const controller = 'did:cel:' + encodedHash;
  // update the DID document and public key with the generated identifier
  didDocument.id = controller;
  publicKey.controller = controller;

  // create a cryptographic proof using ECDSA-JCS-2019
  const ecdsaJcs2019Cryptosuite = createSignCryptosuite();
  const suite = new DataIntegrityProof({
    signer: keyPair.signer(), cryptosuite: ecdsaJcs2019Cryptosuite
  });

  // sign the operation
  let documentLoader = jdl.build();
  const event = {
    operation: {
      type: 'create',
      data: didDocument
    }
  };
  const signedEvent = await jsigs.sign(event, {
    suite,
    purpose: new AssertionProofPurpose(),
    documentLoader
  });
  // delete the @context in the proof as it's unnecessary
  delete signedEvent['@context'];
  delete signedEvent.proof['@context'];

  // TODO: Determine if there is a better way to set the proof VM
  signedEvent.proof.verificationMethod = controller + publicKey.id;

  return {keyPair, event: signedEvent, didDocument};
}

/**
 * Adds a new verification method (VM) to an existing DID document. Generates a
 * new key pair and adds it to the specified verification relationship. The
 * proof is removed and must be regenerated after this operation.
 *
 * @param {Object} options - Configuration options.
 * @param {Object} options.didDocument - The DID document to modify.
 * @param {string} options.verificationRelationship - The verification
 *   relationship to add the key to (e.g., 'assertionMethod', 'authentication',
 *   'keyAgreement').
 * @param {string} [options.curve='P-256'] - The elliptic curve to use for key
 *   generation (e.g., 'P-256', 'P-384').
 * @returns {Promise<Object>} An object containing:
 *   - keyPair: The newly generated ECDSA Multikey key pair
 *   - didDocument: The updated DID document (without proof)
 *
 * @example
 * const {keyPair, didDocument} = await addVm({
 *   didDocument: existingDoc,
 *   verificationRelationship: 'authentication',
 *   curve: 'P-256'
 * });
 */
export async function addVm({didDocument, verificationRelationship, curve}) {
  // TODO: replace with modern clone (structuredClone when available)
  const newDidDocument = JSON.parse(JSON.stringify(didDocument));
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

  // remove old proof (must be regenerated with updateProof function)
  delete newDidDocument.proof;

  // register the new public key with the document loader
  jdl.addStatic(publicKey.id, publicKey);

  return {keyPair, didDocument: newDidDocument};
}

/**
 * Updates or adds a cryptographic proof to a DID document using the specified
 * assertion method key pair. Any existing proof is replaced.
 *
 * @param {Object} options - Configuration options.
 * @param {Object} options.didDocument - The DID document to sign.
 * @param {Object} options.assertionMethod - The key pair to use for signing.
 *   Must have a signer() method and publicKeyMultibase property.
 * @returns {Promise<Object>} An object containing:
 *   - didDocument: The DID document with the new proof attached
 *
 * @example
 * const {didDocument} = await updateProof({
 *   didDocument: modifiedDoc,
 *   assertionMethod: keyPair
 * });
 */
export async function updateProof({didDocument, assertionMethod}) {
  // create a new cryptographic proof using ECDSA-JCS-2019
  let documentLoader = jdl.build();
  const ecdsaJcs2019Cryptosuite = createSignCryptosuite();
  const suite = new DataIntegrityProof({
    signer: assertionMethod.signer(), cryptosuite: ecdsaJcs2019Cryptosuite
  });
  const event = {
    operation: {
      type: 'update',
      data: didDocument
    }
  }
  const signedEvent = await jsigs.sign(event, {
    suite,
    purpose: new AssertionProofPurpose(),
    documentLoader
  });
  // delete the @context in the proof as it's unnecessary
  delete signedEvent.proof['@context'];

  // set the verification method reference in the proof
  // TODO: determine if there is a better way to set verificationMethod
  signedEvent.proof.verificationMethod = didDocument.id + '#' +
    assertionMethod.publicKeyMultibase;

  return {event: signedEvent, didDocument};
}

export default {create, addVm, updateProof};
