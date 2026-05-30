/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {existsSync, mkdirSync, readdirSync, rmSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const TESTS_DIR = path.resolve(__dirname, '..');
export const ROOT_DIR = path.resolve(TESTS_DIR, '..');
export const TMP_DIR = join(TESTS_DIR, 'tmp');
export const LOGS_DIR = join(TMP_DIR, 'logs');
export const SECRETS_DIR = join(TMP_DIR, 'secrets');

export const TEST_PASSWORD = 'test-password-for-automated-tests';
export const TEST_WITNESSES = ['https://localhost:22443/witnesses/test/witness'];

export function clearTmpDir() {
  if(existsSync(TMP_DIR)) {
    for(const entry of readdirSync(TMP_DIR)) {
      rmSync(join(TMP_DIR, entry), {recursive: true, force: true});
    }
  }
  mkdirSync(LOGS_DIR, {recursive: true});
  mkdirSync(SECRETS_DIR, {recursive: true});
}

/**
 * Lists .cel files in the test tmp/logs directory.
 *
 * @returns {Array<string>} Array of filenames.
 */
export function listCelFiles() {
  if(!existsSync(LOGS_DIR)) {
    return [];
  }
  return readdirSync(LOGS_DIR).filter(f => f.endsWith('.cel'));
}

/**
 * Lists .yaml files in the test tmp/secrets directory.
 *
 * @returns {Array<string>} Array of filenames.
 */
export function listSecretFiles() {
  if(!existsSync(SECRETS_DIR)) {
    return [];
  }
  return readdirSync(SECRETS_DIR).filter(f => f.endsWith('.yaml'));
}