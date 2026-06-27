import * as mfHasher from 'multiformats/hashes/hasher';
import {base58btc} from 'multiformats/bases/base58';
import {sha3_256} from '@noble/hashes/sha3.js';

export const VERIFICATION_RELATIONSHIPS =
  ['assertionMethod', 'authentication', 'capabilityDelegation',
    'capabilityInvocation', 'keyAgreement'];

// module-level hasher instance — stateless and reusable across all calls
const _sha3256Hasher = mfHasher.from({
  name: 'sha3-256',
  code: 0x16,
  encode: data => sha3_256(data)
});

/**
 * Computes a SHA3-256 multihash of a UTF-8 string and returns it as a
 * base58btc multibase string (z-prefix). This is the canonical hashing
 * primitive used throughout the did:cel method.
 *
 * @param {string} input - The UTF-8 string to hash.
 * @returns {Promise<string>} Base58btc multibase-encoded SHA3-256 multihash.
 */
export async function sha3256Multibase(input) {
  const mfHash = await _sha3256Hasher.digest(new TextEncoder().encode(input)).bytes;
  return base58btc.encode(mfHash);
}

/**
 * Finds the first object in any array property of a DID document whose id
 * ends with the given suffix. Returns the property name, array index, and
 * entry, or null if not found.
 *
 * @param {object} didDocument - The DID document to search.
 * @param {string} suffix - The id suffix to match.
 * @returns {{property: string, index: number, entry: object}|null}
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
 * Retrieves an object from a DID document by matching the suffix of its id
 * property. Searches through all array properties in the DID document to find
 * an object whose id ends with the specified suffix.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.didDocument - The DID document to search.
 * @param {string} options.suffix - The suffix to match against object ids
 *   (e.g., '#key-1' or 'zDnaeRQ...').
 * @returns {object | undefined} The first object found with a matching id
 *   suffix, or undefined if no match is found.
 *
 * @example
 * const vm = getObjectByIdSuffix({didDocument: doc, suffix: '#key-1'});
 */
export function getObjectByIdSuffix({didDocument, suffix}) {
  return _findByIdSuffix(didDocument, suffix)?.entry;
}

/**
 * Deletes an object from a DID document by matching the suffix of its id
 * property. Searches through all array properties in the DID document and
 * removes the first object whose id ends with the specified suffix. This
 * function mutates the didDocument parameter.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.didDocument - The DID document to modify (mutated in
 *   place).
 * @param {string} options.suffix - The suffix to match against object ids
 *   (e.g., '#key-1' or a multibase encoded key).
 * @returns {object | undefined} The deleted object if found, or undefined if no
 *   match was found.
 *
 * @example
 * const deleted = deleteObjectByIdSuffix({didDocument: doc, suffix: '#key-1'});
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
 * Recursively reorders object keys: @context, id, type first; proof last;
 * everything else sorted alphabetically in between.
 *
 * @param {*} val - Any JSON-serializable value.
 * @returns {*} The value with all nested object keys reordered.
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
 * Post-processes an indented JSON string to collapse adjacent opener lines.
 * When a line ends with [ or { and the next line is a lone opener, the second
 * opener is pulled inline and the block it introduces is de-indented by 2
 * spaces, so e.g. `[\n    {` becomes `[{`.
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

      // Line ends with an opener and next line is a lone opener.
      if(i + 1 < lines.length && /[{\[]\s*$/.test(line)) {
        const m = lines[i + 1].match(/^(\s*)([{\[])\s*$/);
        if(m) {
          const nextOpener = m[2];
          // Find the matching closer by tracking bracket depth.
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
          // Append opener inline; strip 2 leading spaces from interior + closer.
          out.push(line.replace(/\s*$/, '') + nextOpener);
          for(let j = i + 2; j < k; j++) {
            out.push(lines[j].replace(/^  /, ''));
          }
          // Strip 2 spaces from the inner closer, then check if the very next
          // line is also a lone closer — merge them so "}]" lands on one line.
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
 * Pretty-prints a JSON-serializable object with canonical key ordering and
 * collapsed adjacent bracket pairs. Key order: @context, id, type first;
 * proof last; all other keys sorted alphabetically.
 *
 * @param {object} obj - The object to pretty-print.
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
