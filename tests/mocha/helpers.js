/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {deriveHeartbeatKeyPair, sha3256Multibase} from '../../lib/index.js';

export const TEST_PASSWORD = 'test-password-for-automated-tests';
// populated by mock-witness.js start() before tests run
export const TEST_WITNESSES = [];
// DID identifiers of the mock witnesses, used to build trustedWitnesses lists
export const TEST_WITNESS_DIDS = [];

/**
 * Derives the heartbeat key at the given index and returns its did:key hash.
 * This is the value that goes into the DID document's heartbeat[] array.
 *
 * @param {Buffer|Uint8Array} heartbeatSecret - The 16-byte master secret.
 * @param {number} index - The key derivation index.
 * @returns {Promise<string>} Base58btc multibase-encoded SHA3-256 hash.
 */
export async function computeHeartbeatHash(heartbeatSecret, index) {
  const kp = await deriveHeartbeatKeyPair(heartbeatSecret, index);
  const exported = await kp.export({publicKey: true, includeContext: false});
  return sha3256Multibase(`did:key:${exported.publicKeyMultibase}`);
}
