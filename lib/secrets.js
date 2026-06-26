/**
 * @file Encrypted private key storage.
 * Saves and loads private keys to {secretsDir}/{didIdentifier}.yaml.
 * Each secretKeyMultibase is encrypted with AES-256-GCM, with the encryption
 * key derived from a user-supplied password via scrypt.
 */

import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {VERIFICATION_RELATIONSHIPS} from './utils.js';
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs';
import crypto from 'node:crypto';
import {join} from 'node:path';
import yaml from 'js-yaml';

// scrypt parameters: N=2^14, r=8, p=1
const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 32;

/**
 * Encrypts and saves all secret key pairs to the secrets file for a DID.
 *
 * @param {object} options - Configuration options.
 * @param {string} options.didIdentifier - Method-specific ID (part after
 *   did:cel:).
 * @param {object} options.secretKeys - Session secretKeys object keyed by
 *   verification relationship, each an array of keyPair objects.
 * @param {string} options.password - Password used to encrypt each secret key.
 * @param {string} options.secretsDir - Directory path to store the secrets
 *   file.
 */
export async function saveSecrets({
  didIdentifier, secretKeys, password, secretsDir
}) {
  const keys = [];
  for(const [relationship, keyPairs] of Object.entries(secretKeys)) {
    if(relationship === 'heartbeat') {
      continue;
    }
    for(const keyPair of keyPairs) {
      const exported = await keyPair.export(
        {publicKey: true, secretKey: true, includeContext: true});
      const {secretKeyMultibase, ...publicFields} = exported;
      if(!secretKeyMultibase) {
        continue;
      }
      const encryptedSecretKeyMultibase =
        await _encrypt(secretKeyMultibase, password);
      keys.push({...publicFields, relationship, encryptedSecretKeyMultibase});
    }
  }

  // encrypt the heartbeat master secret as multibase base64url
  let encryptedHeartbeatSecret;
  const {heartbeat} = secretKeys;
  if(heartbeat instanceof Uint8Array || Buffer.isBuffer(heartbeat)) {
    const multibase = 'u' + Buffer.from(heartbeat).toString('base64url');
    encryptedHeartbeatSecret = await _encrypt(multibase, password);
  }

  mkdirSync(secretsDir, {recursive: true});
  writeFileSync(
    _secretsPath({didIdentifier, secretsDir}),
    yaml.dump({keys, encryptedHeartbeatSecret})
  );
}

function _secretsPath({didIdentifier, secretsDir}) {
  return join(secretsDir, `${didIdentifier}.yaml`);
}

function _deriveKey(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, KEY_LEN,
      {N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P},
      (err, key) => err ? reject(err) : resolve(key));
  });
}

/**
 * Loads and decrypts private keys from the secrets file for a DID, returning
 * a secretKeys object keyed by verification relationship.
 *
 * @param {object} options - Configuration options.
 * @param {string} options.didIdentifier - Method-specific ID (part after
 *   did:cel:).
 * @param {string} options.password - Password used to decrypt each secret key.
 * @param {string} options.secretsDir - Directory path where the secrets file
 *   is stored.
 * @returns {Promise<object>} SecretKeys object keyed by relationship, each an
 *   array of reconstructed EcdsaMultikey key pair objects.
 */
export async function loadSecrets({didIdentifier, password, secretsDir}) {
  const secretsPath = _secretsPath({didIdentifier, secretsDir});
  if(!existsSync(secretsPath)) {
    throw new Error(`Secrets file not found: ${secretsPath}`);
  }
  const {keys, encryptedHeartbeatSecret} =
    yaml.load(readFileSync(secretsPath, 'utf8')) ?? {keys: []};

  const secretKeys = Object.fromEntries(
    VERIFICATION_RELATIONSHIPS.map(r => [r, []]));


  for(const entry of keys) {
    const {
      relationship, encryptedSecretKeyMultibase, ...publicFields
    } = entry;
    const secretKeyMultibase =
      await _decrypt(encryptedSecretKeyMultibase, password);
    const keyPair = await EcdsaMultikey.from(
      {...publicFields, secretKeyMultibase});
    if(secretKeys[relationship]) {
      secretKeys[relationship].push(keyPair);
    }
  }

  // decrypt heartbeat master secret and return as a Buffer
  if(encryptedHeartbeatSecret) {
    const multibase = await _decrypt(encryptedHeartbeatSecret, password);
    secretKeys.heartbeat = Buffer.from(multibase.slice(1), 'base64url');
  }

  return secretKeys;
}

async function _decrypt(ciphertext, password) {
  const buf = Buffer.from(ciphertext, 'base64');
  const salt = buf.subarray(0, 32);
  const iv = buf.subarray(32, 44);
  const tag = buf.subarray(44, 60);
  const enc = buf.subarray(60);
  const key = await _deriveKey(password, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(enc, undefined, 'utf8') + decipher.final('utf8');
}

async function _encrypt(plaintext, password) {
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const key = await _deriveKey(password, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat(
    [cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // pack: salt(32) || iv(12) || tag(16) || ciphertext, encode as base64
  return Buffer.concat([salt, iv, tag, enc]).toString('base64');
}
