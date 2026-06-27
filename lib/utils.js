import * as mfHasher from 'multiformats/hashes/hasher';
import {base58btc} from 'multiformats/bases/base58';
import {sha3_256} from '@noble/hashes/sha3.js';

export const VERIFICATION_RELATIONSHIPS =
  ['assertionMethod', 'authentication', 'capabilityDelegation',
    'capabilityInvocation', 'keyAgreement'];

// module-level hasher — stateless, reusable across all calls
const _sha3256Hasher = mfHasher.from({
  name: 'sha3-256',
  code: 0x16,
  encode: data => sha3_256(data)
});

/**
 * Returns the base58btc multibase-encoded SHA3-256 multihash of a string.
 * This is the canonical hashing primitive used throughout the did:cel method.
 *
 * @param {string} input - UTF-8 string to hash.
 * @returns {Promise<string>} `z`-prefixed base58btc multibase string.
 */
export async function sha3256Multibase(input) {
  const mfHash =
    await _sha3256Hasher.digest(new TextEncoder().encode(input)).bytes;
  return base58btc.encode(mfHash);
}

/**
 * Finds the first object in any array property of a DID document whose `id`
 * ends with `suffix`. Returns location metadata, or null if not found.
 *
 * @param {object} didDocument - The DID document to search.
 * @param {string} suffix - The id suffix to match.
 * @returns {{property: string, index: number, entry: object}|null} Location
 *   metadata, or null if not found.
 */
function _findByIdSuffix(didDocument, suffix) {
  for(const property of Object.keys(didDocument)) {
    if(!Array.isArray(didDocument[property])) {
      continue;
    }
    const arr = didDocument[property];
    for(let i = 0; i < arr.length; i++) {
      const entry = arr[i];
      if(typeof entry !== 'object') {
        continue;
      }
      if(entry.id.endsWith(suffix)) {
        return {property, index: i, entry};
      }
    }
  }
  return null;
}

/**
 * Returns the first object in any array property of a DID document whose
 * `id` ends with `suffix`, or undefined if not found.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.didDocument - The DID document to search.
 * @param {string} options.suffix - The id suffix to match (e.g. `'#zAbc…'`).
 * @returns {object|undefined} The matched entry, or undefined if not found.
 */
export function getObjectByIdSuffix({didDocument, suffix}) {
  return _findByIdSuffix(didDocument, suffix)?.entry;
}

/**
 * Removes and returns the first object in any array property of a DID
 * document whose `id` ends with `suffix`. Mutates `didDocument` in place.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.didDocument - The DID document to modify.
 * @param {string} options.suffix - The id suffix to match (e.g. `'#zAbc…'`).
 * @returns {object|undefined} The removed object, or undefined if not found.
 */
export function deleteObjectByIdSuffix({didDocument, suffix}) {
  const found = _findByIdSuffix(didDocument, suffix);
  if(!found) {
    return undefined;
  }
  const {property, index, entry} = found;
  didDocument[property].splice(index, 1);
  return entry;
}

/**
 * Recursively reorders object keys for stable JSON output:
 * `@context`, `id`, `type` first; `proof` last; all others alphabetical.
 *
 * @param {*} val - Any JSON-serializable value.
 * @returns {*} Value with all nested object keys reordered.
 */
function _reorder(val) {
  if(Array.isArray(val)) {
    return val.map(_reorder);
  }
  if(val !== null && typeof val === 'object') {
    const FIRST = ['@context', 'id', 'type'];
    const keys = Object.keys(val);
    const ordered = [
      ...FIRST.filter(k => keys.includes(k)),
      ...keys.filter(k => !FIRST.includes(k) && k !== 'proof').sort(),
      ...keys.filter(k => k === 'proof')
    ];
    const out = {};
    for(const k of ordered) {
      out[k] = _reorder(val[k]);
    }
    return out;
  }
  return val;
}

/**
 * Collapses adjacent opener pairs in an indented JSON string so that
 * `[\n    {` becomes `[{`, reducing visual nesting depth.
 *
 * @param {string} str - Indented JSON string.
 * @returns {string} JSON string with adjacent opener pairs collapsed.
 */
function _collapseBrackets(str) {
  let prev;
  do {
    prev = str;
    const lines = str.split('\n');
    const out = [];
    let i = 0;
    while(i < lines.length) {
      const line = lines[i];

      if(i + 1 < lines.length && /[{\[]\s*$/.test(line)) {
        const m = lines[i + 1].match(/^(\s*)([{\[])\s*$/);
        if(m) {
          const nextOpener = m[2];
          let depth = 1;
          let k = i + 2;
          while(k < lines.length && depth > 0) {
            for(const ch of lines[k]) {
              if(ch === '{' || ch === '[') {
                depth++;
              } else if(ch === '}' || ch === ']') {
                depth--;
                if(depth === 0) {
                  break;
                }
              }
            }
            if(depth > 0) {
              k++;
            }
          }
          out.push(line.replace(/\s*$/, '') + nextOpener);
          for(let j = i + 2; j < k; j++) {
            out.push(lines[j].replace(/^  /, ''));
          }
          if(k < lines.length) {
            const innerCloser = lines[k].replace(/^  /, '');
            const outerCloserMatch = k + 1 < lines.length &&
              lines[k + 1].match(/^(\s*)([}\]])(,?)\s*$/);
            if(outerCloserMatch) {
              out.push(
                outerCloserMatch[1] + innerCloser.trim() +
                outerCloserMatch[2] + outerCloserMatch[3]);
              i = k + 2;
            } else {
              out.push(innerCloser);
              i = k + 1;
            }
          } else {
            i = k + 1;
          }
          continue;
        }
      }

      out.push(line);
      i++;
    }
    str = out.join('\n');
  } while(str !== prev);
  return str;
}

/**
 * Serializes a CEL or DID document to a human-readable JSON string with
 * stable key ordering (`@context`/`id`/`type` first, `proof` last,
 * others alphabetical) and collapsed adjacent bracket pairs.
 *
 * @param {object} obj - The object to serialize.
 * @returns {string} Formatted JSON string.
 */
export function prettyPrintCel(obj) {
  return _collapseBrackets(JSON.stringify(_reorder(obj), null, 2));
}

export default {
  deleteObjectByIdSuffix,
  getObjectByIdSuffix,
  prettyPrintCel,
  sha3256Multibase
};
