# didcel

A JavaScript library for creating and managing Decentralized Identifiers (DIDs)
using the Cryptographic Event Log (CEL) method. This library provides functions
for working with `did:cel` identifiers, which use a witness-based architecture
to maintain a cryptographically verifiable history of DID document operations.

The `did:cel` method is a fully decentralized DID method that doesn't depend on
blockchains, centralized registries, or any single point of control. Instead, it
uses cryptographic event logs with independent witness attestations to create
tamper-evident audit trails for DID operations.

## Installation

### Prerequisites

- Node.js v24 or higher
- npm (comes with Node.js)

### Install Dependencies

```bash
npm install
```

## Library API

All public functions are exported from the package entry point:

```js
import {
  // DID document operations
  create, addVm, createEvent, hashDidKey, setHeartbeatFrequency,
  // CEL operations
  createCel, addEvent, getPreviousEventHash, witness,
  read, loadFromFile, saveToFile,
  // Secret key storage
  saveSecrets, loadSecrets,
  // Utilities
  createJsonldPrettyPrinter, getObjectByIdSuffix, deleteObjectByIdSuffix,
  // Low-level witness HTTP client
  witnessService
} from 'didcel';
```

---

### `create([options])` -> `{keyPair, heartbeatKeyPair, didDocument, cryptographicEventLog}`

Creates a new `did:cel` DID document with a self-certifying identifier, an
initial assertion method key pair, a heartbeat key pair, and an initial signed
create event already wrapped in a Cryptographic Event Log.

| Parameter | Type | Description |
|-----------|------|-------------|
| `options.curve` | string | Elliptic curve for key generation. Default: `'P-256'`. |
| `options.heartbeatFrequency` | string | ISO 8601 duration for the required heartbeat interval. Default: `'P10Y'`. |

```js
const {keyPair, heartbeatKeyPair, didDocument, cryptographicEventLog} =
  await create();

console.log(didDocument.id); // did:cel:z...
```

---

### `addVm({didDocument, verificationRelationship, [curve]})` -> `{keyPair, didDocument}`

Generates a new key pair and adds it as a verification method to the specified
relationship in the DID document. Removes the existing proof since the document
must be re-signed with `createEvent` before appending an update event.

| Parameter | Type | Description |
|-----------|------|-------------|
| `didDocument` | object | The current DID document. |
| `verificationRelationship` | string | One of `'authentication'`, `'assertionMethod'`, `'capabilityInvocation'`, `'capabilityDelegation'`, `'keyAgreement'`. |
| `curve` | string | Elliptic curve. Default: `'P-256'`. |

```js
const {keyPair: authKeyPair, didDocument: updatedDoc} = await addVm({
  didDocument,
  verificationRelationship: 'authentication'
});
```

---

### `createEvent({type, data, assertionMethod, previousEventHash})` -> `Promise<{event}>`

Creates a signed event of the given type using the provided assertion method key.
Use this for `'update'`, `'heartbeat'`, and `'deactivate'` events after the
initial create. Always call `getPreviousEventHash()` first and pass the result
as `previousEventHash` so the hash is covered by the operation proof.

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Event type: `'update'`, `'heartbeat'`, or `'deactivate'`. |
| `data` | object\|undefined | The DID document for update events; `undefined` for heartbeat and deactivate. |
| `assertionMethod` | KeyPair | The key pair to sign with (from `assertionMethod` in the DID document, or the heartbeat key pair). |
| `previousEventHash` | string | Base58btc SHA3-256 hash of the previous event from `getPreviousEventHash()`. |

```js
const previousEventHash =
  await getPreviousEventHash({cel: cryptographicEventLog});
const {event} = await createEvent({
  type: 'update',
  data: updatedDidDocument,
  assertionMethod: keyPair,
  previousEventHash
});
```

---

### `getPreviousEventHash({cel})` -> `Promise<string|undefined>`

Computes the SHA3-256 multibase hash of the most recent event in a CEL. Pass
the result as `previousEventHash` to `createEvent` before signing, so the
hash chain is covered by the operation proof.

```js
const previousEventHash = await getPreviousEventHash({cel: cryptographicEventLog});
```

---

### `addEvent({cel, event})` -> `Promise<cel>`

Appends a pre-signed event to the CEL. The event must already contain a
`previousEventHash` (set before signing via `getPreviousEventHash`) so the
hash is included in the operation proof. Call `witness()` after appending
to obtain attestations.

```js
await addEvent({cel: cryptographicEventLog, event});
```

---

### `witness({cel, witnesses})` -> `Promise<Array>`

Obtains cryptographic attestations from witness services for the most recent
event in the CEL. Each witness receives only a SHA3-256 hash of the event
(blind witness - they never see the DID document) and returns a
`DataIntegrityProof` that provides temporal anchoring and distributed trust.

| Parameter | Type | Description |
|-----------|------|-------------|
| `cel` | object | The Cryptographic Event Log. |
| `witnesses` | string[] | Array of witness service URLs. |

```js
await witness({
  cel: cryptographicEventLog,
  witnesses: ['https://witness.example/witnesses/v1']
});
```

---

### `setHeartbeatFrequency({didDocument, heartbeatFrequency})` -> `{didDocument}`

Updates the `heartbeatFrequency` field on a DID document and removes the proof.
The document must be re-signed with `createEvent` before appending an update
event.

| Parameter | Type | Description |
|-----------|------|-------------|
| `didDocument` | object | The current DID document. |
| `heartbeatFrequency` | string | ISO 8601 duration (e.g. `'P3M'`, `'P1Y'`). |

```js
const {didDocument: updatedDoc} = setHeartbeatFrequency({
  didDocument,
  heartbeatFrequency: 'P3M'
});
```

---

### `hashDidKey(didKey)` -> `Promise<string>`

Computes the base58btc-encoded SHA3-256 multihash of a `did:key` URI. This is
the value stored in the `heartbeat` array of a DID document.

```js
const heartbeatHash = await hashDidKey('did:key:z...');
```

---

### `saveToFile({filename, cel})`

Saves a CEL to a gzip-compressed JSON file.

```js
saveToFile({filename: './logs/my-did.cel', cel: cryptographicEventLog});
```

---

### `loadFromFile({filename, [trustedWitnesses], [versionTime]})` -> `Promise<{cel, valid, errors, didDocument}>`

Loads a gzip-compressed CEL file and fully validates it:

- Self-certifying DID identifier integrity
- Hash chain integrity (`previousEventHash` on each non-create entry)
- Operation proof signatures (ecdsa-jcs-2019)
- Witness proof signatures (blind-witness scheme)
- Timestamp deviation between operation and witness proofs (<= 5 min)
- Heartbeat key rotation rules
- Heartbeat frequency compliance

| Parameter | Type | Description |
|-----------|------|-------------|
| `filename` | string | Path to the `.cel` file. |
| `trustedWitnesses` | Array | Optional. Each entry: `{id, validFrom, validUntil}`. Only proofs from listed witnesses within their validity window are verified. |
| `versionTime` | string | Optional ISO datetime. When set, entries whose earliest trusted witness timestamp exceeds this time are excluded, enabling historical DID resolution. |

Returns `{cel, valid, errors, didDocument}` where `valid` is `false` and
`errors` is non-empty if any check fails.

```js
const trustedWitnesses = [{
  id: 'did:key:z...',
  validFrom: '2024-01-01T00:00:00Z',
  validUntil: '2099-01-01T00:00:00Z'
}];
const {valid, errors, didDocument} = await loadFromFile({
  filename: './logs/my-did.cel',
  trustedWitnesses
});
if(!valid) {
  console.error('CEL validation failed:', errors);
}
```

---

### `read({cel, [trustedWitnesses], [versionTime]})` -> `Promise<{cel, valid, errors, didDocument}>`

Same validation as `loadFromFile` but operates on an already-parsed CEL object
instead of reading from disk. Accepts the same `trustedWitnesses` and
`versionTime` options.

---

### `saveSecrets({didIdentifier, secretKeys, password, secretsDir})`

Encrypts all private keys with AES-256-GCM (key derived via scrypt) and saves
them to `{secretsDir}/{didIdentifier}.yaml`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `didIdentifier` | string | Method-specific ID (the part after `did:cel:`). |
| `secretKeys` | object | Keys organized by verification relationship, each an array of key pair objects. |
| `password` | string | Password used to encrypt each private key. |
| `secretsDir` | string | Directory path to write the secrets file. |

```js
const secretKeys = {
  assertionMethod: [keyPair],
  authentication: [],
  capabilityInvocation: [],
  capabilityDelegation: [],
  keyAgreement: []
};
await saveSecrets({didIdentifier, secretKeys, password, secretsDir});
```

---

### `loadSecrets({didIdentifier, password, secretsDir})` -> `Promise<secretKeys>`

Loads and decrypts private keys from `{secretsDir}/{didIdentifier}.yaml`,
returning a `secretKeys` object keyed by verification relationship.

```js
const secretKeys = await loadSecrets({didIdentifier, password, secretsDir});
const signingKey = secretKeys.assertionMethod[0];
```

---

## Typical Workflow

```js
import {join} from 'node:path';
import {
  addEvent, addVm, create, createEvent, getPreviousEventHash,
  loadFromFile, loadSecrets, saveSecrets, saveToFile, witness
} from 'didcel';

const WITNESSES = ['https://witness.example/witnesses/v1'];
const LOGS_DIR = './logs';
const SECRETS_DIR = './secrets';
const PASSWORD = process.env.DID_PASSWORD;

// 1. Create a new DID (returns CEL pre-loaded with the create event)
const {keyPair, heartbeatKeyPair, didDocument, cryptographicEventLog} =
  await create();

// 2. Witness the create event
await witness({cel: cryptographicEventLog, witnesses: WITNESSES});

// 3. Add an authentication key
const {keyPair: authKeyPair, didDocument: updatedDoc} = await addVm({
  didDocument,
  verificationRelationship: 'authentication'
});

// 4. Sign and append an update event
const previousEventHash =
  await getPreviousEventHash({cel: cryptographicEventLog});
const {event: updateEvent} = await createEvent({
  type: 'update',
  data: updatedDoc,
  assertionMethod: keyPair,
  previousEventHash
});
await addEvent({cel: cryptographicEventLog, event: updateEvent});
await witness({cel: cryptographicEventLog, witnesses: WITNESSES});

// 5. Save the CEL and encrypted secrets
const didIdentifier = didDocument.id.replace('did:cel:', '');
saveToFile({
  filename: join(LOGS_DIR, `${didIdentifier}.cel`),
  cel: cryptographicEventLog
});

const secretKeys = {
  assertionMethod: [keyPair],
  authentication: [authKeyPair],
  capabilityInvocation: [],
  capabilityDelegation: [],
  keyAgreement: []
};
await saveSecrets({didIdentifier, secretKeys, password: PASSWORD, secretsDir: SECRETS_DIR});

// 6. Later: load and verify the CEL
const trustedWitnesses = [{
  id: 'did:key:z...',  // the witness's DID
  validFrom: '2024-01-01T00:00:00Z',
  validUntil: '2099-01-01T00:00:00Z'
}];
const {valid, errors} = await loadFromFile({
  filename: join(LOGS_DIR, `${didIdentifier}.cel`),
  trustedWitnesses
});
console.log('CEL valid:', valid, errors);
```

## Architecture

The library implements the `did:cel` DID method, which consists of:

- **Self-certifying identifiers:** DID identifiers derived from a SHA3-256 hash
  of the canonicalized initial DID document (without `id` or `controller`
  fields), encoded as `did:cel:` + base58btc multibase.
- **Cryptographic Event Log (CEL):** A hash-linked chain of events recording all
  DID operations (`create`, `update`, `heartbeat`, `deactivate`), each signed
  with ecdsa-jcs-2019. Non-create events include a `previousEventHash` that
  is set before signing so the hash chain is covered by the operation proof.
- **Blind witness attestations:** Witness services receive only a SHA3-256 hash
  of each event and return `DataIntegrityProof` attestations, providing temporal
  anchoring and distributed trust without learning DID document contents.
- **Heartbeat keys:** Each DID document stores SHA3-256 hashes of heartbeat
  `did:key:` URIs. A heartbeat operation signs an update with the heartbeat key
  and must rotate out the used hash, replacing it with a new one.
- **Encrypted secret storage:** Private keys encrypted with AES-256-GCM using a
  scrypt-derived key and stored in YAML format.

## File Structure

- `lib/index.js` - Package entry point; explicit named exports for all public functions
- `lib/didcel.js` - DID document operations: `create`, `addVm`, `createEvent`, `setHeartbeatFrequency`, `hashDidKey`
- `lib/cel.js` - Cryptographic Event Log: `createCel`, `addEvent`, `getPreviousEventHash`, `witness`, `read`, `loadFromFile`, `saveToFile`
- `lib/secrets.js` - Encrypted key storage: `saveSecrets`, `loadSecrets`
- `lib/witness.js` - HTTP client for witness services
- `lib/utils.js` - JSON-LD key ordering and suffix-based lookup utilities
- `lib/validate.js` - AJV JSON Schema validation for DID documents and CELs

## Security Considerations

- **Secret Keys:** Private keys are held in memory as key pair objects. Call
  `saveSecrets` to persist them encrypted to disk; they are lost otherwise.
- **Blind Witnesses:** Witness services never see the DID document - they only
  sign a SHA3-256 hash of the event. This prevents witnesses from learning
  private information about DID controllers.
- **CEL Files:** Saved CEL files contain only public information (DID documents
  and proofs), not private keys.
- **Heartbeat Keys:** Heartbeat key hashes are stored in the DID document. A
  heartbeat operation requires proving possession of a heartbeat key and rotating
  its hash out of the document to prevent replay attacks.

## License

BSD-3-Clause

## Contributing

This is an experimental implementation of the `did:cel` DID method. Contributions
and feedback are welcome.

## Related Specifications

- [DID CEL Specification](https://w3c-ccg.github.io/did-cel-spec/) - Technical specification for the `did:cel` method
- [W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/) - Core DID specification
- [Verifiable Credential Data Integrity](https://www.w3.org/TR/vc-data-integrity/) - Data Integrity Proofs specification
