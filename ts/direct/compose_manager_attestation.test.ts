import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  canonicalActionsJson,
  composeManagerActionsHash,
} from './compose_manager_attestation';

test('matches Compose Manager canonical action hashing', () => {
  const actions = [
    {
      timestamp: '2026-01-01T00:00:00+00:00',
      action: 'compose_up',
      tag: 'v1',
    },
  ];

  assert.equal(
    canonicalActionsJson(actions),
    '[{"action":"compose_up","tag":"v1","timestamp":"2026-01-01T00:00:00+00:00"}]',
  );
  assert.equal(
    composeManagerActionsHash(actions),
    '381eb48dc299dafbbcd49c1a009998240f641865f35e435d2f07385c6e6b2a23',
  );
});
