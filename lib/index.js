// cel.js: Cryptographic Event Log management
export {addEvent, create as createCel, load, witness} from './cel.js';

// didcel.js: DID document creation and management
export {addVm, create, createEvent} from './didcel.js';

// secrets.js: Encrypted private key storage
export {loadSecrets, saveSecrets} from './secrets.js';

// utils.js: JSON-LD utilities
export {
  createJsonldPrettyPrinter,
  deleteObjectByIdSuffix,
  getObjectByIdSuffix
} from './utils.js';

// witness.js: Witness service HTTP client
export {witness as witnessService} from './witness.js';
