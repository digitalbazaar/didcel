/**
 * Creates a JSON-LD pretty printer function that orders object keys according
 * to a preferred order, with remaining keys sorted alphabetically.
 *
 * @param {Object} options - Configuration options.
 * @param {Array<string>} options.preferOrder - Array of keys to appear first
 *   in the specified order (e.g., ['@context', 'id', 'type']).
 * @returns {Function} A replacer function for use with JSON.stringify() that
 *   orders object properties according to the preferred order.
 *
 * @example
 * const printer = createJsonldPrettyPrinter({
 *   preferOrder: ['@context', 'id', 'type']
 * });
 * JSON.stringify(obj, printer, 2);
 */
export function createJsonldPrettyPrinter({preferOrder}) {
  return (key, value) => {
    let result = value;
    // only process objects (not arrays or primitives)
    if(value instanceof Object && !(value instanceof Array)) {
      let sortedKeys = Object.keys(value).sort();
      let prettyKeys = [];

      // first, add keys that are in the preferred order
      for(let pkey of preferOrder) {
        if(value[pkey] !== undefined) {
          prettyKeys.push(pkey);
        }
      }
      // then, add remaining keys in alphabetical order
      for(let skey of sortedKeys) {
        if(!preferOrder.includes(skey)) {
          prettyKeys.push(skey);
        }
      }

      // reconstruct the object with the new key order
      result = prettyKeys.reduce((sorted, key) => {
        sorted[key] = value[key];
        return sorted;
      }, {});
    }

    return result;
  }
}

/**
 * Retrieves an object from a DID document by matching the suffix of its id
 * property. Searches through all array properties in the DID document to find
 * an object whose id ends with the specified suffix.
 *
 * @param {Object} options - Configuration options.
 * @param {Object} options.didDocument - The DID document to search.
 * @param {string} options.suffix - The suffix to match against object ids
 *   (e.g., '#key-1' or 'zDnaeRQ...').
 * @returns {Object|undefined} The first object found with a matching id suffix,
 *   or undefined if no match is found.
 *
 * @example
 * const vm = getObjectByIdSuffix({
 *   didDocument: doc,
 *   suffix: '#key-1'
 * });
 */
export function getObjectByIdSuffix({didDocument, suffix}) {
  let rval = undefined;
  // iterate through all properties in the DID document
  for(let property of Object.keys(didDocument)) {
    // only process array properties (e.g., assertionMethod, authentication)
    if(!Array.isArray(didDocument[property])) {
      continue;
    }
    // search through each entry in the array
    for(let entry of didDocument[property]) {
      // skip non-object entries
      if(typeof entry !== 'object') {
        continue;
      }
      // extract the suffix portion of the entry's id
      const idSuffix =
        entry.id.slice(entry.id.length - suffix.length, entry.id.length);
      // check if the id suffix matches the target suffix
      if(suffix === idSuffix) {
        rval = entry;
      }
    }
  }

  return rval;
}

/**
 * Deletes an object from a DID document by matching the suffix of its id
 * property. Searches through all array properties in the DID document and
 * removes the first object whose id ends with the specified suffix. This
 * function mutates the didDocument parameter.
 *
 * @param {Object} options - Configuration options.
 * @param {Object} options.didDocument - The DID document to modify (mutated in
 *   place).
 * @param {string} options.suffix - The suffix to match against object ids
 *   (e.g., '#key-1' or a multibase encoded key).
 * @returns {Object|undefined} The deleted object if found, or undefined if no
 *   match was found.
 *
 * @example
 * const deleted = deleteObjectByIdSuffix({
 *   didDocument: doc,
 *   suffix: '#key-1'
 * });
 */
export function deleteObjectByIdSuffix({didDocument, suffix}) {
  let rval = undefined;
  // iterate through all properties in the DID document
  for(let property of Object.keys(didDocument)) {
    // only process array properties (e.g., assertionMethod, authentication)
    if(!Array.isArray(didDocument[property])) {
      continue;
    }

    // filter out the entry with matching id suffix
    didDocument[property] = didDocument[property].filter((entry) => {
      // keep non-object entries
      if(typeof entry !== 'object') {
        return true;
      }
      // extract the suffix portion of the entry's id
      const idSuffix =
        entry.id.slice(entry.id.length - suffix.length, entry.id.length);
      // if suffix doesn't match, keep the entry
      if(suffix !== idSuffix) {
        return true;
      } else {
        // if suffix matches, store the entry and remove it from the array
        rval = entry;
        return false;
      }
    })
  }

  return rval;
}

export default {
  createJsonldPrettyPrinter,
  deleteObjectByIdSuffix,
  getObjectByIdSuffix
};
