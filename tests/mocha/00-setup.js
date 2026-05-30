/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
import {start, stop} from './mock-witness.js';

before(() => start());
after(() => stop());
