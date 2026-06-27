/**
 * @file HTTP client for the did:cel blind witness service.
 */

import fetch from 'node-fetch';
import https from 'node:https';

// allow self-signed certs on localhost https witness services
const httpsAgent = new https.Agent({rejectUnauthorized: false});

/**
 * Sends a `digestMultibase` to a witness service and returns its proof.
 *
 * @param {object} options - Configuration options.
 * @param {string} options.digestMultibase - Base58btc SHA3-256 multihash of
 *   the event to attest (`z`-prefixed).
 * @param {string} options.witnessUrl - Witness endpoint URL.
 * @returns {Promise<object>} DataIntegrityProof returned by the witness.
 */
export async function witness({digestMultibase, witnessUrl}) {
  const {protocol} = new URL(witnessUrl);
  const agent = protocol === 'https:' ? httpsAgent : undefined;
  const response = await fetch(witnessUrl, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({digestMultibase}),
    agent
  });
  if(!response.ok) {
    const body = await response.text();
    throw new Error(`Witness request failed (${response.status}): ${body}`);
  }
  const {proof} = await response.json();
  return proof;
}

export default {witness};
