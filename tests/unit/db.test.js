import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { queryRecords } from '../../src/db.js';

describe('Database Module & Parameterized SQL Invariants', () => {
  describe('Input Validation Constraints', () => {
    it('should reject non-numeric string IDs with HTTP 400 error status', async () => {
      await assert.rejects(
        async () => {
          await queryRecords({ id: "1' OR '1'='1" });
        },
        (err) => {
          assert.equal(err.status, 400);
          assert.match(err.message, /positive integer/);
          return true;
        },
      );
    });

    it('should reject non-positive IDs (0 or negative) with HTTP 400 error status', async () => {
      await assert.rejects(
        async () => {
          await queryRecords({ id: 0 });
        },
        (err) => {
          assert.equal(err.status, 400);
          return true;
        },
      );

      await assert.rejects(
        async () => {
          await queryRecords({ id: -42 });
        },
        (err) => {
          assert.equal(err.status, 400);
          return true;
        },
      );
    });
  });

  describe('Parameterized Query Architecture (Negative Control)', () => {
    it('should pass parameters as isolated array elements and never interpolate raw strings', () => {
      // Static inspection verifying prepared statements use $1 / $2 placeholders
      const queryFunctionText = queryRecords.toString();

      // Assert that SQL queries use parameter placeholders
      assert.match(queryFunctionText, /WHERE id = \$1/);
      assert.match(queryFunctionText, /WHERE action ILIKE \$1 OR details ILIKE \$1/);

      // Assert that string concatenation into SQL is strictly absent
      assert.doesNotMatch(queryFunctionText, /WHERE id = \$\{/);
      assert.doesNotMatch(queryFunctionText, /WHERE action ILIKE '%'\s*\+/);
      assert.doesNotMatch(queryFunctionText, /WHERE id = '\s*\+/);
    });
  });
});
