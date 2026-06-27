/**
 * @file JSON Schema validation for did:cel DID documents and CELs.
 */

import addFormats from 'ajv-formats';
import Ajv from 'ajv/dist/2020.js';

const ajv = new Ajv({allErrors: true, strict: false});
addFormats(ajv);

// Reusable sub-schemas
const MULTIBASE_STRING = {type: 'string', pattern: '^z[1-9A-HJ-NP-Za-km-z]+'};
const DID_CEL = {type: 'string', pattern: '^did:cel:z[1-9A-HJ-NP-Za-km-z]+'};
const ISO_DATETIME = {type: 'string'};
const ISO_DURATION = {type: 'string', pattern: '^P'};

const VERIFICATION_METHOD = {
  type: 'object',
  required: ['id', 'type', 'controller'],
  properties: {
    id: {type: 'string'},
    type: {type: 'string', enum: ['Multikey', 'JsonWebKey']},
    controller: {type: 'string'},
    publicKeyMultibase: MULTIBASE_STRING,
    publicKeyJwk: {type: 'object'}
  },
  additionalProperties: true
};

const SERVICE_ENTRY = {
  type: 'object',
  required: ['type', 'serviceEndpoint'],
  properties: {
    type: {type: 'string', const: 'CelStorageService'},
    serviceEndpoint: {
      type: 'array',
      items: {type: 'string', format: 'uri'},
      minItems: 1
    }
  },
  additionalProperties: true
};

const DID_DOCUMENT_SCHEMA = {
  type: 'object',
  required: ['@context', 'id', 'heartbeatFrequency', 'assertionMethod',
    'heartbeat', 'service'],
  properties: {
    '@context': {
      type: 'array',
      prefixItems: [
        {type: 'string', const: 'https://www.w3.org/ns/did/v1.1'},
        {type: 'string', const: 'https://w3id.org/didcel/v1'}
      ],
      minItems: 2,
      items: {type: 'string'}
    },
    id: DID_CEL,
    heartbeatFrequency: ISO_DURATION,
    assertionMethod: {
      type: 'array',
      items: VERIFICATION_METHOD,
      minItems: 1
    },
    authentication: {type: 'array', items: VERIFICATION_METHOD},
    keyAgreement: {type: 'array', items: VERIFICATION_METHOD},
    capabilityDelegation: {type: 'array', items: VERIFICATION_METHOD},
    capabilityInvocation: {type: 'array', items: VERIFICATION_METHOD},
    heartbeat: {
      type: 'array',
      items: MULTIBASE_STRING,
      minItems: 1
    },
    service: {
      type: 'array',
      items: SERVICE_ENTRY,
      minItems: 1
    }
  },
  additionalProperties: true
};

const DATA_INTEGRITY_PROOF = {
  type: 'object',
  required: ['type', 'cryptosuite', 'proofPurpose', 'proofValue',
    'verificationMethod'],
  properties: {
    type: {type: 'string', const: 'DataIntegrityProof'},
    cryptosuite: {type: 'string'},
    created: ISO_DATETIME,
    proofPurpose: {type: 'string'},
    proofValue: MULTIBASE_STRING,
    verificationMethod: {type: 'string'}
  },
  additionalProperties: true
};

// Witness proofs additionally require `created`
const WITNESS_PROOF = {
  ...DATA_INTEGRITY_PROOF,
  required: [...DATA_INTEGRITY_PROOF.required, 'created']
};

const CREATE_OPERATION = {
  type: 'object',
  required: ['type', 'data'],
  properties: {
    type: {type: 'string', const: 'create'},
    data: DID_DOCUMENT_SCHEMA
  },
  additionalProperties: false
};

const UPDATE_OPERATION = {
  type: 'object',
  required: ['type', 'data'],
  properties: {
    type: {type: 'string', const: 'update'},
    data: DID_DOCUMENT_SCHEMA
  },
  additionalProperties: false
};

const HEARTBEAT_OPERATION = {
  type: 'object',
  required: ['type', 'data'],
  properties: {
    type: {type: 'string', const: 'heartbeat'},
    data: {
      type: 'object',
      required: ['heartbeat'],
      properties: {
        heartbeat: {type: 'array', items: MULTIBASE_STRING, minItems: 1}
      },
      additionalProperties: false
    }
  },
  additionalProperties: false
};

const DEACTIVATE_OPERATION = {
  type: 'object',
  required: ['type'],
  properties: {
    type: {type: 'string', const: 'deactivate'}
  },
  additionalProperties: false
};

const CREATE_EVENT = {
  type: 'object',
  required: ['operation', 'proof'],
  properties: {
    '@context': {},
    operation: CREATE_OPERATION,
    proof: DATA_INTEGRITY_PROOF
  },
  additionalProperties: false
};

const NON_CREATE_EVENT = {
  type: 'object',
  required: ['previousEventHash', 'operation', 'proof'],
  properties: {
    '@context': {},
    previousEventHash: MULTIBASE_STRING,
    operation: {oneOf: [UPDATE_OPERATION, HEARTBEAT_OPERATION, DEACTIVATE_OPERATION]},
    proof: DATA_INTEGRITY_PROOF
  },
  additionalProperties: false
};

const CREATE_LOG_ENTRY = {
  type: 'object',
  required: ['event'],
  properties: {
    event: CREATE_EVENT,
    proof: {type: 'array', items: WITNESS_PROOF}
  },
  additionalProperties: false
};

const NON_CREATE_LOG_ENTRY = {
  type: 'object',
  required: ['event'],
  properties: {
    event: NON_CREATE_EVENT,
    proof: {type: 'array', items: WITNESS_PROOF}
  },
  additionalProperties: false
};

const CEL_SCHEMA = {
  type: 'object',
  required: ['log'],
  properties: {
    log: {
      type: 'array',
      minItems: 1,
      prefixItems: [CREATE_LOG_ENTRY],
      items: NON_CREATE_LOG_ENTRY
    }
  },
  additionalProperties: false
};

const validateDidDocument = ajv.compile(DID_DOCUMENT_SCHEMA);
const validateCel = ajv.compile(CEL_SCHEMA);

/**
 * Throws if `didDocument` does not conform to the did:cel JSON Schema.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.didDocument - The DID document to validate.
 * @throws {Error} Describing all schema violations.
 */
export function assertValidDidDocument({didDocument}) {
  if(!validateDidDocument(didDocument)) {
    const details = ajv.errorsText(
      validateDidDocument.errors, {separator: '; '});
    throw new Error(`Invalid DID document: ${details}`);
  }
}

/**
 * Throws if `cel` does not conform to the did:cel JSON Schema.
 *
 * @param {object} options - Configuration options.
 * @param {object} options.cel - The CEL to validate.
 * @throws {Error} Describing all schema violations.
 */
export function assertValidCel({cel}) {
  if(!validateCel(cel)) {
    const details = ajv.errorsText(validateCel.errors, {separator: '; '});
    throw new Error(`Invalid CEL: ${details}`);
  }
}

export default {assertValidCel, assertValidDidDocument};
