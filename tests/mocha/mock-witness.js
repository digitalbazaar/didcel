/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */

/**
 * Minimal mock HTTP server implementing the did:cel blind-witness endpoint.
 * Accepts POST {digestMultibase, options} and returns
 * {proof: DataIntegrityProof}.
 *
 * VerifyData = SHA256(JCS(proofOptions)) || rawHash, where rawHash is the
 * 32-byte SHA2-256 digest extracted from the received multihash. This matches
 * exactly what `_verifyWitnessProof()` in cel.js reconstructs.
 */
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {TEST_WITNESS_DIDS, TEST_WITNESSES} from './helpers.js';
import {base58btc} from 'multiformats/bases/base58';
import canonicalize from 'canonicalize';
import crypto from 'node:crypto';
import http from 'node:http';

// SHA2-256 multihash header: function code 0x12, digest size 32 (0x20)
const SHA2_256_HEADER = new Uint8Array([0x12, 0x20]);

let _server = null;
let _keyPair = null;
let _verificationMethod = null;

export async function start() {
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
  TEST_WITNESSES.push(url);
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
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    const {
      digestMultibase,
      options: {cryptosuite = 'ecdsa-jcs-2019'} = {}
    } = JSON.parse(Buffer.concat(chunks).toString());

    if(cryptosuite !== 'ecdsa-jcs-2019') {
      res.writeHead(400, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({error: `unsupported cryptosuite ${cryptosuite}`}));
      return;
    }

    // validate the sha2-256 multihash header and strip it to get the
    // raw 32-byte digest
    const mhBytes = base58btc.decode(digestMultibase);
    if(mhBytes.length !== SHA2_256_HEADER.length + 32 ||
      mhBytes[0] !== SHA2_256_HEADER[0] || mhBytes[1] !== SHA2_256_HEADER[1]) {
      res.writeHead(400, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({
        error: 'digestMultibase must be a base58btc-encoded sha2-256 ' +
          'multihash value'
      }));
      return;
    }
    const rawHash = mhBytes.slice(SHA2_256_HEADER.length);

    const proofOptions = {
      '@context': 'https://w3id.org/security/data-integrity/v2',
      created: new Date().toISOString(),
      cryptosuite,
      proofPurpose: 'assertionMethod',
      type: 'DataIntegrityProof',
      verificationMethod: _verificationMethod
    };

    // verifyData = SHA256(JCS(proofOptions)) || rawHash
    const c14nProof = canonicalize(proofOptions);
    const proofHash = new Uint8Array(
      crypto.createHash('sha256').update(c14nProof).digest());
    const verifyData = new Uint8Array(proofHash.length + rawHash.length);
    verifyData.set(proofHash, 0);
    verifyData.set(rawHash, proofHash.length);

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
