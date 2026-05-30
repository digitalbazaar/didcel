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

All functions are exported from the package entry point:

```js
import {
  create, createCel, witness, addVm, createEvent, addEvent, load,
  saveSecrets, loadSecrets
} from 'didcel';
```

---

### `create([options])` → `{keyPair, recoveryKeyPair, event, didDocument}`

Creates a new `did:cel` DID document with a self-certifying identifier and an
initial signed create event.

| Parameter | Type | Description |
|-----------|------|-------------|
| `options.curve` | string | Elliptic curve for key generation. Default: `'P-256'`. |

```js
const {keyPair, recoveryKeyPair, event, didDocument} = await create();

console.log(didDocument.id); // did:cel:z...
```

---

### `createCel({event})` → `cel`

Initializes a new Cryptographic Event Log with the create event.

```js
const cel = createCel({event});
```

---

### `witness({cel, witnesses})` → `Promise<Array>`

Obtains cryptographic attestations from witness services for the most recent
event in the CEL. Each witness independently signs a hash of the event, creating
a `DataIntegrityProof` that provides temporal anchoring and distributed
validation.

| Parameter | Type | Description |
|-----------|------|-------------|
| `cel` | object | The Cryptographic Event Log. |
| `witnesses` | string[] | Array of witness service URLs. |

```js
await witness({
  cel,
  witnesses: ['https://witness.example/witnesses/v1']
});
```

---

### `addVm({didDocument, verificationRelationship, [curve]})` → `{keyPair, didDocument}`

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

### `createEvent({type, data, assertionMethod})` → `Promise<{event}>`

Creates a signed event of the given type using the provided assertion method key.
Use this for `'update'`, `'heartbeat'`, and `'deactivate'` events after the
initial create.

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Event type: `'update'`, `'heartbeat'`, or `'deactivate'`. |
| `data` | object\|undefined | The DID document for update events; `undefined` for heartbeat and deactivate. |
| `assertionMethod` | KeyPair | The key pair to sign with (from `assertionMethod` in the DID document). |

```js
const {event} = await createEvent({
  type: 'update',
  data: updatedDidDocument,
  assertionMethod: keyPair
});
```

---

### `addEvent({cel, event})` → `Promise<cel>`

Appends an event to the CEL, hash-linking it to the previous event via a
SHA3-256 `previousEventHash`. Call `witness()` after appending to obtain
attestations.

```js
await addEvent({cel, event});
```

---

### `load({filename})` → `Promise<{cel, valid, errors, didDocument}>`

Loads a CEL from a JSON file and fully validates it:

- Hash chain integrity (`previousEventHash` on each non-create entry)
- Operation proof signatures (ecdsa-jcs-2019)
- Witness proof signatures (blind-witness scheme)
- Timestamp deviation between operation and witness proofs (≤ 5 min)

| Parameter | Type | Description |
|-----------|------|-------------|
| `filename` | string | Path to the `.cel` file. |

Returns `{cel, valid, errors, didDocument}` where `valid` is `false` and
`errors` is non-empty if any check fails.

```js
const {cel, valid, errors, didDocument} = await load({filename: 'my-did.cel'});
if(!valid) {
  console.error('CEL validation failed:', errors);
}
```

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

### `loadSecrets({didIdentifier, password, secretsDir})` → `Promise<secretKeys>`

Loads and decrypts private keys from `{secretsDir}/{didIdentifier}.yaml`,
returning a `secretKeys` object keyed by verification relationship.

```js
const secretKeys = await loadSecrets({didIdentifier, password, secretsDir});
const signingKey = secretKeys.assertionMethod[0];
```

---

## Typical Workflow

```js
import {writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {
  addEvent, addVm, create, createCel, createEvent, load,
  loadSecrets, saveSecrets, witness
} from 'didcel';

const WITNESSES = ['https://witness.example/witnesses/v1'];
const LOGS_DIR = './logs';
const SECRETS_DIR = './secrets';
const PASSWORD = process.env.DID_PASSWORD;

// 1. Create a new DID
const {keyPair, recoveryKeyPair, event, didDocument} = await create();
const cel = createCel({event});

// 2. Witness the create event
await witness({cel, witnesses: WITNESSES});

// 3. Add an authentication key
const {keyPair: authKeyPair, didDocument: updatedDoc} = await addVm({
  didDocument,
  verificationRelationship: 'authentication'
});

// 4. Sign and append an update event
const {event: updateEvent} = await createEvent({
  type: 'update',
  data: updatedDoc,
  assertionMethod: keyPair
});
await addEvent({cel, event: updateEvent});
await witness({cel, witnesses: WITNESSES});

// 5. Save the CEL and encrypted secrets
const didIdentifier = didDocument.id.replace('did:cel:', '');
writeFileSync(join(LOGS_DIR, `${didIdentifier}.cel`), JSON.stringify(cel));

const secretKeys = {
  assertionMethod: [keyPair],
  authentication: [authKeyPair],
  capabilityInvocation: [],
  capabilityDelegation: [],
  keyAgreement: [],
  recovery: [recoveryKeyPair]
};
await saveSecrets({didIdentifier, secretKeys, password: PASSWORD, secretsDir: SECRETS_DIR});

// 6. Later: load and verify the CEL
const {valid, errors} = await load({
  filename: join(LOGS_DIR, `${didIdentifier}.cel`)
});
console.log('CEL valid:', valid, errors);
```

## Architecture

The library implements the `did:cel` DID method, which consists of:

- **Self-certifying identifiers:** DID identifiers derived from a SHA3-256 hash
  of the canonicalized initial DID document, encoded in base58btc.
- **Cryptographic Event Log (CEL):** A hash-linked chain of events recording all
  DID operations (`create`, `update`, `heartbeat`, `deactivate`), each signed
  with ecdsa-jcs-2019.
- **Witness attestations:** Independent `DataIntegrityProof` attestations from
  witness services, providing temporal evidence and distributed validation.
- **Encrypted secret storage:** Private keys encrypted with AES-256-GCM using a
  scrypt-derived key and stored in YAML format.

## File Structure

- `lib/index.js` — Package entry point; explicit named exports for all public functions
- `lib/didcel.js` — DID document operations: `create`, `addVm`, `createEvent`
- `lib/cel.js` — Cryptographic Event Log: `createCel`, `addEvent`, `witness`, `load`
- `lib/secrets.js` — Encrypted key storage: `saveSecrets`, `loadSecrets`
- `lib/witness.js` — HTTP client for witness services
- `lib/utils.js` — JSON-LD key ordering and suffix-based lookup utilities

## Security Considerations

- **Secret Keys:** Private keys are held in memory as key pair objects. Call
  `saveSecrets` to persist them encrypted to disk; they are lost otherwise.
- **Witness Services:** Witnesses must be independent services with securely
  managed keys. The witness URL array is passed directly to `witness()` — no
  configuration files are used.
- **CEL Files:** Saved CEL files contain only public information (DID documents
  and proofs), not private keys.

## License

BSD-3-Clause

## Contributing

This is an experimental implementation of the `did:cel` DID method. Contributions
and feedback are welcome.

## Related Specifications

- [DID CEL Specification](https://digitalbazaar.github.io/did-cel-spec/) — Technical specification for the `did:cel` method
- [W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/) — Core DID specification
- [Verifiable Credential Data Integrity](https://www.w3.org/TR/vc-data-integrity/) — Data Integrity Proofs specification