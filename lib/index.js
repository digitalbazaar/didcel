// cel.js: CEL read, write, and validation
export {
  addEvent, create as createCel, getPreviousEventHash, loadFromFile, read,
  saveToFile, witness
} from './cel.js';

// didcel.js: DID document creation and management
export {
  addVm, create, createEvent, deriveHeartbeatKeyPair, setHeartbeatFrequency
} from './didcel.js';

// secrets.js: encrypted private key storage
export {loadSecrets, saveSecrets} from './secrets.js';

// utils.js: hashing, pretty-printing, and DID document utilities
export {
  deleteObjectByIdSuffix,
  getObjectByIdSuffix,
  prettyPrintCel,
  sha2256Multibase,
  sha3256Multibase,
  VERIFICATION_RELATIONSHIPS
} from './utils.js';

// witness.js: witness service HTTP client
export {witness as witnessService} from './witness.js';
