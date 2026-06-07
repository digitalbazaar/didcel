/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */

/**
 * Minimal mock HTTP server that implements the hmbd blind-witness endpoint.
 *
 * The protocol:
 *   POST {url}  body: {digestMultibase}
 *   Response:   {proof: DataIntegrityProof}
 *
 * The witness signs verifyData = SHA256(canonicalize(proofOptions)) || rawHash
 * where rawHash is the 32-byte SHA2-256 digest extracted from the received
 * multihash. This exactly matches what cel.js _verifyWitnessProof() expects.
 */
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {base58btc} from 'multiformats/bases/base58';
import {TEST_WITNESSES, TEST_WITNESS_DIDS} from './helpers.js';
import canonicalize from 'canonicalize';
import crypto from 'node:crypto';
import http from 'node:http';

// SHA3-256 multihash header is 2 bytes: [0x16, 0x20]
const MULTIHASH_HEADER_LENGTH = 2;

let _server = null;
let _keyPair = null;
let _verificationMethod = null;

export async function start() {
  // generate a fresh witness key pair for this test run
  _keyPair = await EcdsaMultikey.generate({curve: 'P-256'});
  const exported =
    await _keyPair.export({publicKey: true, includeContext: false});
  const {publicKeyMultibase} = exported;
  const didKeyId = `did:key:${publicKeyMultibase}`;
  _verificationMethod = `${didKeyId}#${publicKeyMultibase}`;

  _server = http.createServer(_handleRequest);
  await new Promise(resolve => _server.listen(0, '127.0.0.1', resolve));

  const {port} = _server.address();
  const url = `http://127.0.0.1:${port}/witness`;
  // populate the shared TEST_WITNESSES array so all test files see it
  TEST_WITNESSES.push(url);
  // expose the witness DID so tests can build trustedWitnesses lists
  TEST_WITNESS_DIDS.push(didKeyId);
}

export function stop() {
  return new Promise(resolve => {
    if(_server) {
      _server.close(resolve);
      _server = null;
    } else {
      resolve();
    }
  });
}

async function _handleRequest(req, res) {
  if(req.method !== 'POST') {
    res.writeHead(405);
    res.end();
    return;
  }

  try {
    // collect request body
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    const {digestMultibase} = JSON.parse(Buffer.concat(chunks).toString());

    // extract the raw 32-byte SHA2-256 digest from the base58btc multihash
    const mhBytes = base58btc.decode(digestMultibase);
    const rawHash = mhBytes.slice(MULTIHASH_HEADER_LENGTH);

    // build proof options — everything the proof will contain except proofValue
    const proofOptions = {
      '@context': 'https://w3id.org/security/data-integrity/v2',
      created: new Date().toISOString(),
      cryptosuite: 'ecdsa-jcs-2019',
      proofPurpose: 'assertionMethod',
      type: 'DataIntegrityProof',
      verificationMethod: _verificationMethod
    };

    // verifyData = SHA256(canonicalize(proofOptions)) || rawHash
    // this must exactly match what _verifyWitnessProof() reconstructs in cel.js
    const c14nProof = canonicalize(proofOptions);
    const proofHash = new Uint8Array(
      crypto.createHash('sha256').update(c14nProof).digest());
    const verifyData = new Uint8Array(proofHash.length + rawHash.length);
    verifyData.set(proofHash, 0);
    verifyData.set(rawHash, proofHash.length);

    // sign and base58btc-encode (includes 'z' multibase prefix)
    const signer = _keyPair.signer();
    const signatureBytes = await signer.sign({data: verifyData});
    const proofValue = base58btc.encode(signatureBytes);

    const proof = {...proofOptions, proofValue};
    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({proof}));
  } catch(e) {
    res.writeHead(500);
    res.end(JSON.stringify({error: e.message}));
  }
}