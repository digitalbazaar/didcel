// cel.js: Cryptographic Event Log management
export {
  addEvent, create as createCel, getPreviousEventHash, loadFromFile, read,
  saveToFile, witness
} from './cel.js';

// didcel.js: DID document creation and management
export {
  addVm, create, createEvent, deriveHeartbeatKeyPair, setHeartbeatFrequency
} from './didcel.js';

// secrets.js: Encrypted private key storage
export {loadSecrets, saveSecrets} from './secrets.js';

// utils.js: JSON-LD utilities and hashing primitives
export {
  createJsonldPrettyPrinter,
  deleteObjectByIdSuffix,
  getObjectByIdSuffix,
  hashDidKey
} from './utils.js';

// witness.js: Witness service HTTP client
export {witness as witnessService} from './witness.js';
