import assert from 'node:assert/strict';
import { test } from 'node:test';
import { formatDate, formatDateTime, formatTime } from '../lib/datetime.ts';

// Node re-reads TZ on assignment, standing in for the viewer's browser timezone.
function inZone(zone, run) {
  const previous = process.env.TZ;
  process.env.TZ = zone;
  try { run(); } finally { if (previous === undefined) delete process.env.TZ; else process.env.TZ = previous; }
}
test('dates use an ordinal day, short month and full year', () => inZone('UTC', () => {
  assert.equal(formatDate('2026-10-14T09:30:00Z'), '14th Oct 2026');
  assert.deepEqual([1, 2, 3, 4, 11, 12, 13, 21, 22, 23, 31].map(day => formatDate(Date.UTC(2026, 0, day))),
    ['1st Jan 2026', '2nd Jan 2026', '3rd Jan 2026', '4th Jan 2026', '11th Jan 2026', '12th Jan 2026', '13th Jan 2026', '21st Jan 2026', '22nd Jan 2026', '23rd Jan 2026', '31st Jan 2026']);
  assert.equal(formatDate('2026-09-02T00:00:00Z'), '2nd Sep 2026');
}));
test('UTC timestamps convert to the browser timezone, including across the date line', () => {
  inZone('Asia/Kolkata', () => assert.equal(formatDateTime('2026-10-14T20:15:07Z'), '15th Oct 2026, 01:45:07'));
  inZone('America/Los_Angeles', () => assert.equal(formatDateTime('2026-10-14T03:00:00Z'), '13th Oct 2026, 20:00:00'));
  inZone('UTC', () => assert.equal(formatTime(Date.UTC(2026, 9, 14, 7, 5, 9)), '07:05:09'));
});
test('unparseable values are shown as received', () => {
  assert.equal(formatDate('not a date'), 'not a date');
  assert.equal(formatDateTime(''), '');
});
