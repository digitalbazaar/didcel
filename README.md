# didcel

JavaScript library for creating and managing Decentralized Identifiers (DIDs)
using the `did:cel` method. DIDs are secured by a Cryptographic Event Log (CEL)
— a hash-linked chain of witnessed events — with no dependency on blockchains or
centralized registries.

## Installation

```bash
npm install
```

Requires Node.js v24+.

## API

All public functions are exported from the package entry point:

```js
import {
  // DID document operations
  create, addVm, createEvent, deriveHeartbeatKeyPair,
  hashDidKey, setHeartbeatFrequency,
  // CEL operations
  addEvent, getPreviousEventHash, witness,
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

### `create([options])` → `{keyPair, heartbeatSecret, didDocument, cryptographicEventLog}`

Creates a new `did:cel` DID. Returns the assertion method key pair, a 16-byte
heartbeat master secret, the signed DID document, and a CEL pre-loaded with the
create event.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `options.curve` | string | `'P-256'` | Elliptic curve for key generation. |
| `options.heartbeatFrequency` | string | `'P1M'` | Required heartbeat interval (ISO 8601 duration). |

```js
const {keyPair, heartbeatSecret, didDocument, cryptographicEventLog} =
  await create();
// didDocument.id === 'did:cel:z...'
```

---

### `deriveHeartbeatKeyPair(masterSecret, index)` → `Promise<KeyPair>`

Derives the heartbeat key pair at a given index from the master secret returned
by `create()`. The key at index 0 corresponds to the hash already in
`didDocument.heartbeat`. Every CEL operation (except deactivate) must be signed
with the currently active heartbeat key and must rotate to the next key.

| Parameter | Type | Description |
|-----------|------|-------------|
| `masterSecret` | Buffer | 16-byte heartbeat master secret from `create()`. |
| `index` | number | Key index. Start at 0; increment after each rotation. |

```js
const hbKey0 = await deriveHeartbeatKeyPair(heartbeatSecret, 0);
const hbKey1 = await deriveHeartbeatKeyPair(heartbeatSecret, 1);
```

---

### `hashDidKey(didKey)` → `Promise<string>`

Converts a `did:key:` URI to the base58btc multibase hash stored in
`didDocument.heartbeat`.

```js
const exported = await hbKey1.export({publicKey: true, includeContext: false});
const nextHash = await hashDidKey(`did:key:${exported.publicKeyMultibase}`);
```

---

### `createEvent({type, data, signer, previousEventHash})` → `Promise<{event}>`

Creates and signs a CEL event. All events must be signed by the **currently
active heartbeat key** (from `deriveHeartbeatKeyPair`). Every event except
`deactivate` must rotate the heartbeat key by including the next heartbeat hash
in `data`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | `'update'`, `'heartbeat'`, or `'deactivate'`. |
| `data` | object\|undefined | DID document for `update`; `{heartbeat: ["<next_hash>"]}` for `heartbeat`; `undefined` for `deactivate`. |
| `signer` | KeyPair | The active heartbeat key pair. |
| `previousEventHash` | string | Hash of the previous event from `getPreviousEventHash()`. |

```js
// update: full DID document with rotated heartbeat hash
const {event: updateEvent} = await createEvent({
  type: 'update',
  data: {...updatedDoc, heartbeat: [nextHash]},
  signer: hbKey0,
  previousEventHash
});

// heartbeat: partial object with only the new heartbeat hash
const {event: hbEvent} = await createEvent({
  type: 'heartbeat',
  data: {heartbeat: [nextHash]},
  signer: hbKey0,
  previousEventHash
});

// deactivate: no data, no rotation needed
const {event: deactivateEvent} = await createEvent({
  type: 'deactivate',
  signer: hbKey0,
  previousEventHash
});
```

---

### `getPreviousEventHash({cel})` → `Promise<string>`

Returns the hash of the most recent event in the CEL. Call this before
`createEvent()` and pass the result as `previousEventHash` so the hash is
covered by the operation proof.

```js
const previousEventHash = await getPreviousEventHash({cel: cryptographicEventLog});
```

---

### `addEvent({cel, event})` → `Promise<cel>`

Appends a pre-signed event to the CEL. Throws `MALFORMED_CEL_ERROR` if the log
is empty or already deactivated.

```js
await addEvent({cel: cryptographicEventLog, event});
```

---

### `witness({cel, witnesses})` → `Promise<Array>`

Obtains witness attestations for the most recent event. Call after every
`addEvent()`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `cel` | object | The CEL. |
| `witnesses` | string[] | Witness service URLs. |

```js
await witness({
  cel: cryptographicEventLog,
  witnesses: ['https://witness.example/witnesses/v1']
});
```

---

### `addVm({didDocument, verificationRelationship, [curve]})` → `{keyPair, didDocument}`

Generates a new key pair and adds it to the specified verification relationship.
The returned document has its proof removed and must be re-signed via
`createEvent` before appending to the CEL.

| Parameter | Type | Description |
|-----------|------|-------------|
| `didDocument` | object | The current DID document. |
| `verificationRelationship` | string | `'authentication'`, `'assertionMethod'`, `'capabilityInvocation'`, `'capabilityDelegation'`, or `'keyAgreement'`. |
| `curve` | string | Elliptic curve. Default: `'P-256'`. |

```js
const {keyPair: authKeyPair, didDocument: updatedDoc} = await addVm({
  didDocument,
  verificationRelationship: 'authentication'
});
```

---

### `setHeartbeatFrequency({didDocument, heartbeatFrequency})` → `{didDocument}`

Updates `heartbeatFrequency` on a DID document and removes the proof. The
document must be re-signed via `createEvent` before appending to the CEL.

```js
const {didDocument: updatedDoc} = setHeartbeatFrequency({
  didDocument,
  heartbeatFrequency: 'P1W'
});
```

---

### `saveToFile({filename, cel})`

Saves a CEL to a gzip-compressed file.

```js
saveToFile({filename: './logs/my-did.cel', cel: cryptographicEventLog});
```

---

### `loadFromFile({filename, [trustedWitnesses], [versionTime]})` → `Promise<{cel, valid, errors, didDocument}>`

Loads and validates a CEL file. Returns `valid: false` and a non-empty `errors`
array if any check fails (identifier integrity, hash chain, operation and witness
proof signatures, timestamp deviation, heartbeat rotation, heartbeat frequency).

| Parameter | Type | Description |
|-----------|------|-------------|
| `filename` | string | Path to the `.cel` file. |
| `trustedWitnesses` | `{id, validFrom, validUntil}[]` | Witnesses to verify. Only proofs from listed witnesses within their validity window are checked. |
| `versionTime` | string | ISO datetime for historical DID resolution. Entries witnessed after this time are excluded. |

```js
const {valid, errors, didDocument} = await loadFromFile({
  filename: './logs/my-did.cel',
  trustedWitnesses: [{
    id: 'did:key:z...',
    validFrom: '2024-01-01T00:00:00Z',
    validUntil: '2099-01-01T00:00:00Z'
  }]
});
```

---

### `read({cel, [trustedWitnesses], [versionTime]})` → `Promise<{cel, valid, errors, didDocument}>`

Same as `loadFromFile` but accepts an already-parsed CEL object.

---

### `saveSecrets({didIdentifier, secretKeys, password, secretsDir})`

Encrypts private keys with AES-256-GCM and saves them to
`{secretsDir}/{didIdentifier}.yaml`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `didIdentifier` | string | The method-specific ID (everything after `did:cel:`). |
| `secretKeys` | object | Keys by relationship. Verification relationships hold arrays of key pairs; `heartbeat` holds the 16-byte master secret Buffer. |
| `password` | string | Encryption password. |
| `secretsDir` | string | Directory to write into. |

```js
await saveSecrets({
  didIdentifier,
  secretKeys: {
    assertionMethod: [keyPair],
    authentication: [],
    capabilityInvocation: [],
    capabilityDelegation: [],
    keyAgreement: [],
    heartbeat: heartbeatSecret
  },
  password,
  secretsDir
});
```

---

### `loadSecrets({didIdentifier, password, secretsDir})` → `Promise<secretKeys>`

Decrypts and returns private keys. `secretKeys.heartbeat` is a 16-byte Buffer
(the master secret); each other field is an array of key pair objects.

```js
const secretKeys = await loadSecrets({didIdentifier, password, secretsDir});
const hbKey = await deriveHeartbeatKeyPair(secretKeys.heartbeat, currentIndex);
```

---

## Heartbeat Key Rotation

Every event signed after `create` uses the **heartbeat key** derived at the
current rotation index. Each event (except `deactivate`) must advance the index
by including the hash of the *next* key in the event data, and must not reuse a
key whose hash is still in `didDocument.heartbeat`.

```
index 0 → signs create  (hash of key 0 placed in didDocument.heartbeat at create time)
index 0 → signs event 1 (data includes hash of key 1; hash of key 0 is removed)
index 1 → signs event 2 (data includes hash of key 2; hash of key 1 is removed)
...
index N → signs deactivate (no rotation needed)
```

---

## Typical Workflow

```js
import {join} from 'node:path';
import {
  addEvent, addVm, create, createEvent, deriveHeartbeatKeyPair,
  getPreviousEventHash, hashDidKey, loadFromFile, loadSecrets,
  saveSecrets, saveToFile, witness
} from 'didcel';

const WITNESSES = ['https://witness.example/witnesses/v1'];
const LOGS_DIR = './logs';
const SECRETS_DIR = './secrets';
const PASSWORD = process.env.DID_PASSWORD;

// Helper: compute hash of heartbeat key at given index
async function hbHash(secret, index) {
  const kp = await deriveHeartbeatKeyPair(secret, index);
  const exp = await kp.export({publicKey: true, includeContext: false});
  return hashDidKey(`did:key:${exp.publicKeyMultibase}`);
}

// 1. Create a new DID
const {keyPair, heartbeatSecret, didDocument, cryptographicEventLog} =
  await create();
await witness({cel: cryptographicEventLog, witnesses: WITNESSES});

// 2. Update: add authentication key, rotate heartbeat key 0 → 1
const hbKey0 = await deriveHeartbeatKeyPair(heartbeatSecret, 0);
const {didDocument: updatedDoc} =
  await addVm({didDocument, verificationRelationship: 'authentication'});
updatedDoc.heartbeat = [await hbHash(heartbeatSecret, 1)];

const {event: updateEvent} = await createEvent({
  type: 'update',
  data: updatedDoc,
  signer: hbKey0,
  previousEventHash: await getPreviousEventHash({cel: cryptographicEventLog})
});
await addEvent({cel: cryptographicEventLog, event: updateEvent});
await witness({cel: cryptographicEventLog, witnesses: WITNESSES});

// 3. Save the CEL and encrypted secrets
const didIdentifier = didDocument.id.replace('did:cel:', '');
saveToFile({
  filename: join(LOGS_DIR, `${didIdentifier}.cel`),
  cel: cryptographicEventLog
});
await saveSecrets({
  didIdentifier,
  secretKeys: {
    assertionMethod: [keyPair],
    authentication: [],
    capabilityInvocation: [],
    capabilityDelegation: [],
    keyAgreement: [],
    heartbeat: heartbeatSecret
  },
  password: PASSWORD,
  secretsDir: SECRETS_DIR
});

// 4. Later: load and verify
const {valid, errors, didDocument: resolved} = await loadFromFile({
  filename: join(LOGS_DIR, `${didIdentifier}.cel`),
  trustedWitnesses: [{
    id: 'did:key:z...',
    validFrom: '2024-01-01T00:00:00Z',
    validUntil: '2099-01-01T00:00:00Z'
  }]
});
```

---

## Architecture

- **Self-certifying identifiers:** The DID is derived from a hash of the initial
  DID document, so its integrity can be verified without any external registry.
- **Cryptographic Event Log (CEL):** Each operation (`create`, `update`,
  `heartbeat`, `deactivate`) is signed with the active heartbeat key and
  hash-linked to the previous event. Non-create events carry a `previousEventHash`
  that is set before signing, so the hash chain is covered by the proof.
- **Blind witnesses:** Witnesses receive only a hash of each event, never the DID
  document, and return a `DataIntegrityProof` for temporal anchoring.
- **Heartbeat keys:** A 16-byte master secret is stored; individual keys are
  derived on demand. Each key is one-time-use — its hash is rotated out of
  `didDocument.heartbeat` when it signs an event. The `deactivate` event is the
  only exception: no rotation is required.
- **Encrypted secrets:** Private keys are encrypted with AES-256-GCM (scrypt key
  derivation) and stored as YAML.

## File Structure

| File | Contents |
|------|----------|
| `lib/index.js` | Package entry point; all public exports |
| `lib/didcel.js` | `create`, `addVm`, `createEvent`, `setHeartbeatFrequency`, `hashDidKey`, `deriveHeartbeatKeyPair` |
| `lib/cel.js` | `addEvent`, `getPreviousEventHash`, `witness`, `read`, `loadFromFile`, `saveToFile` |
| `lib/secrets.js` | `saveSecrets`, `loadSecrets` |
| `lib/witness.js` | HTTP client for witness services |
| `lib/utils.js` | JSON-LD key ordering; suffix-based document lookup utilities |
| `lib/validate.js` | AJV JSON Schema validation for DID documents and CELs |

## License

BSD-3-Clause
