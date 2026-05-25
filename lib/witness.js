/**
 * @fileoverview Witness service HTTP client.
 * Calls a real blind witness service to obtain a DataIntegrityProof attesting
 * to a cryptographic event hash.
 */

import fetch from 'node-fetch';
import https from 'node:https';

// allow self-signed certs on localhost witness services
const httpsAgent = new https.Agent({rejectUnauthorized: false});

/**
 * Sends a digestMultibase to a witness service and returns the proof.
 *
 * @param {Object} options
 * @param {string} options.digestMultibase - base58btc-encoded SHA2-256
 *   multihash of the event to attest (z prefix).
 * @param {string} options.witnessUrl - Full URL of the witness endpoint.
 * @returns {Promise<Object>} DataIntegrityProof returned by the witness.
 */
export async function witness({digestMultibase, witnessUrl}) {
  const response = await fetch(witnessUrl, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({digestMultibase}),
    agent: httpsAgent
  });
  if(!response.ok) {
    const body = await response.text();
    throw new Error(`Witness request failed (${response.status}): ${body}`);
  }
  const {proof} = await response.json();
  return proof;
}

export default {witness};
