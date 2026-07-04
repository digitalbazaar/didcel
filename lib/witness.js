/**
 * @file HTTP client for the did:cel blind witness service.
 */

import fetch from 'node-fetch';
import https from 'node:https';

/**
 * Sends a `digestMultibase` to a witness service and returns its proof.
 *
 * @param {object} options - Configuration options.
 * @param {string} options.digestMultibase - Base58btc SHA2-256 multihash of
 *   the event to attest (`z`-prefixed).
 * @param {string} options.witnessUrl - Witness endpoint URL.
 * @param {boolean} [options.allowSelfSigned=false] - When true, accept
 *   self-signed TLS certificates. Only enable this for local development;
 *   never use in production.
 * @param {string} [options.cryptosuite='ecdsa-jcs-2019'] - Data integrity
 *   cryptosuite the witness is asked to use for its proof.
 * @returns {Promise<object>} DataIntegrityProof returned by the witness.
 */
export async function witness({
  digestMultibase, witnessUrl, allowSelfSigned,
  cryptosuite = 'ecdsa-jcs-2019'
}) {
  const {protocol} = new URL(witnessUrl);
  let agent;
  if(protocol === 'https:' && allowSelfSigned) {
    agent = new https.Agent({rejectUnauthorized: false});
  }
  const response = await fetch(witnessUrl, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({digestMultibase, options: {cryptosuite}}),
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
