/**
 * @fileoverview Witness service for CEL event attestation.
 * This module manages witness key pairs and generates cryptographic proofs
 * that attest to the validity of CEL events. Witnesses provide independent
 * validation of DID operations.
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
const jdl = new JsonLdDocumentLoader();

// TODO: move to separate service -- generate all of the witness keys
// hardcoded witness keys for development/testing purposes
// in production, these should be securely managed and not stored in code
const secretKeys = [{
  "@context": "https://w3id.org/security/multikey/v1",
  "id": "did:web:red-witness.example#vm-red-1",
  "type": "Multikey",
  "controller": "did:web:red-witness.example",
  "publicKeyMultibase": "zDnaeRQKUJYxFwB1zgHisFGeHXYhgoDkXQ3cgzTJHVPfxtfxY",
  "secretKeyMultibase": "z42twzpeKSKsX7NNH5v4CGREKhmcEKGu5RXXAVQQCqjDMnPg"
}, {
  "@context": "https://w3id.org/security/multikey/v1",
  "id": "did:web:green-witness.example#vm-green-1",
  "type": "Multikey",
  "controller": "did:web:green-witness.example",
  "publicKeyMultibase": "zDnaecDuyWKVKwfHEZrh6bNtLDK46Y88nGLEEEjqcTbCYwWYW",
  "secretKeyMultibase": "z42tp2TDou6md8m7oq78f52mdYCDdUwSqhuvYEPsdG6cXGHo"
}, {
  "@context": "https://w3id.org/security/multikey/v1",
  "id": "did:web:blue-witness.example#vm-blue-1",
  "type": "Multikey",
  "controller": "did:web:blue-witness.example",
  "publicKeyMultibase": "zDnaeo6TCxLGbQ2G1k4jvzv5keBaaADp8v7vgiYLbi2heCFPF",
  "secretKeyMultibase": "z42ttRq6VGC727Z4F5c8q6zjBvgJ6MTT3t16JoJEWFzujeSq"
}];

// initialize witness key pairs and register them with the document loader
let witnesses = {};
for(let secretKey of secretKeys) {
 // import the ECDSA Multikey from the secret key
  const keyPair =
    await EcdsaMultikey.from(secretKey);
  const publicKey =
    await keyPair.export({publicKey: true, includeContext: false});
  const exportedKeyPair =
    await keyPair.export({publicKey: true, secretKey: true});

 // store the witness key pair indexed by controller DID
  witnesses[secretKey.controller] = {secretKey, keyPair};
 // register the public key with the document loader for verification
  jdl.addStatic(publicKey.id, publicKey);
}


/**
 * Generates a cryptographic proof for data using a specified witness key.
 * The proof attests that the witness has validated the data.
 *
 * @param {Object} options - Configuration options.
 * @param {Object} options.data - The data to sign (typically a CEL event).
 * @param {Object} options.options - Configuration containing witness selection.
 * @param {string} options.options.witness - The DID of the witness to use for signing
 *   (e.g., 'did:web:red-witness.example').
 * @returns {Promise<Object>} A Data Integrity Proof object containing the
 *   cryptographic signature and metadata.
 *
 * @example
 * const proof = await generateProof({
 *   data: celEvent,
 *   options: {witness: 'did:web:red-witness.example'}
 * });
 */
export async function generateProof({data, options}) {
 // retrieve the key pair for the specified witness
  const keyPair = witnesses[options.witness].keyPair;
 // create ECDSA-JCS-2019 cryptosuite for signing
  const ecdsaJcs2019Cryptosuite = createSignCryptosuite();
  const suite = new DataIntegrityProof({
    signer: keyPair.signer(), cryptosuite: ecdsaJcs2019Cryptosuite
  });

 // sign the data and generate the proof
  let documentLoader = jdl.build();
  const signedData = await jsigs.sign(data, {
    suite,
    purpose: new AssertionProofPurpose(),
    documentLoader
  });

 // return only the proof portion (not the entire signed data)
  return signedData.proof;
}

export default {generateProof};
