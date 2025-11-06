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

export async function create({options}) {
  const keyPair =
    await EcdsaMultikey.generate({curve: options?.curve || 'P-256'});
  const publicKey =
    await keyPair.export({publicKey: true, includeContext: false});
  publicKey.id = '#' + publicKey.publicKeyMultibase;

  // update document loader
  jdl.addStatic(publicKey.id, publicKey);

  let didDocument = {
    '@context': 'https://www.w3.org/ns/did/v1.1',
    assertionMethod: [publicKey]
  }

  // generate the did:cel identifier
  const utf8Encoder = new TextEncoder();
  const canonicalizedDidDocument = canonicalize(didDocument);
  console.log(canonicalizedDidDocument);
  const sha3256Hasher = mfHasher.from({
    name: 'sha3-256',
    code: 0x16,
    encode: input => sha3_256(input),
  });
  const mfHash = await sha3256Hasher.digest(
    utf8Encoder.encode(canonicalizedDidDocument)).bytes;
  const encodedHash = base58btc.encode(mfHash);
  const controller = 'did:cel:' + encodedHash;
  didDocument.id = controller;
  publicKey.controller = controller;

  // place a proof on the DID Document
  const ecdsaJcs2019Cryptosuite = createSignCryptosuite();
  const suite = new DataIntegrityProof({
    signer: keyPair.signer(), cryptosuite: ecdsaJcs2019Cryptosuite
  });

  // create signed credential
  let documentLoader = jdl.build();
  const signedDidDocument = await jsigs.sign(didDocument, {
    suite,
    purpose: new AssertionProofPurpose(),
    documentLoader
  });

  // rewrite DID Document to place the `id` at the top of the document
  didDocument = {
    '@context': 'https://www.w3.org/ns/did/v1.1',
    id: controller,
    assertionMethod: [publicKey],
    proof: signedDidDocument.proof
  }

  return {keyPair, didDocument};
}

export function update({cel, data, options}) {
  // TODO: Calculate hash of previous event
  let previousEvent = 'TODO';

  // push event to end of log
  cel.log.push({
    event: {
      previousEvent,
      operation: {
        type: 'update',
        data
      }
    }
  });

  return log;
}

export default {create, update};
