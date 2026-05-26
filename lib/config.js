/**
 * @file Configuration loader.
 * Reads config.yaml from a given path, defaulting to ~/.config/didcel/.
 * Call loadConfig() before accessing config properties.
 */

import {existsSync, readFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {join} from 'node:path';
import yaml from 'js-yaml';

export const DEFAULT_CONFIG_PATH =
  join(homedir(), '.config', 'didcel', 'config.yaml');

// resolve leading ~/ in path values to the user's home directory
function _resolvePath(value) {
  if(typeof value === 'string' && value.startsWith('~/')) {
    return join(homedir(), value.slice(2));
  }
  return value;
}

// mutable config object populated by loadConfig()
export const config = {};

/**
 * Loads and validates the configuration file.
 *
 * @param {object} [options={}] - Configuration options.
 * @param {string} [options.configPath] - Path to config.yaml; defaults to
 *   ~/.config/didcel/config.yaml.
 */
export function loadConfig({configPath = DEFAULT_CONFIG_PATH} = {}) {
  if(!existsSync(configPath)) {
    throw new Error(`Configuration file not found: ${configPath}`);
  }
  const raw = yaml.load(readFileSync(configPath, 'utf8')) ?? {};
  Object.assign(config, {
    ...raw,
    logs: _resolvePath(raw.logs),
    secrets: _resolvePath(raw.secrets)
  });
}
