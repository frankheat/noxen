const test = require('node:test');
const assert = require('node:assert/strict');
const { snapshotCursor, previewCursor, validateTable, buildCursor } = require('../agent/provider_cursor.js');
function fixture(rows, position = -1) {
  return {
    position, getPosition() { return this.position; }, getCount: () => rows.length,
    getColumnNames: () => ['text', 'integer', 'nullable'],
    moveToPosition(row) { this.position = row; return row >= 0 && row < rows.length; },
    getType(col) { return [3, 1, 0][col]; },
    getString(col) { return rows[this.position][col]; },
    getLong(col) { return rows[this.position][col]; },
  };
}
test('preview returns a complete small result and a partial large result without changing position', () => {
  for (const count of [0, 1, 100, 101]) {
    const cursor = fixture(Array(count).fill(['first', '1', null]), -1);
    cursor.getCount = () => { throw new Error('Preview must not ask for the count'); };
    const preview = previewCursor(cursor);
    assert.equal(preview.complete, count <= 100);
    assert.equal(preview.rows.length, Math.min(count, 100));
    assert.equal(cursor.position, -1);
  }
});
test('preview restores position after a cell read fails and stops at its byte budget', () => {
  const broken = fixture([['first', '1', null], ['second', '2', null]], 1);
  broken.getString = () => { throw new Error('Read failed'); };
  assert.throws(() => previewCursor(broken), /Read failed/);
  assert.equal(broken.position, 1);
  const large = fixture(Array(10).fill(['ç'.repeat(8192), '1', null]));
  const preview = previewCursor(large);
  assert.equal(preview.reason, 'Size limit reached');
  assert.equal(preview.rows.length, 3);
  assert.equal(large.position, -1);
});
test('snapshot restores before-first, selected and after-last positions and preserves int64', () => {
  for (const position of [-1, 0, 1]) {
    const cursor = fixture([['name', '9223372036854775807', null]], position);
    const table = snapshotCursor(cursor);
    assert.equal(cursor.position, position);
    assert.deepEqual(table.rows[0], [{type:'string',value:'name'}, {type:'integer',value:'9223372036854775807'}, {type:'null',value:null}]);
  }
});
test('unsupported cells and excessive rows never produce a partial editable table', () => {
  const cursor = fixture([['a', '1', null]]);
  cursor.getType = () => 4;
  assert.throws(() => snapshotCursor(cursor), /Blob/);
  assert.equal(cursor.position, -1);
  const many = fixture(Array(101).fill(['a', '1', null]));
  assert.throws(() => snapshotCursor(many), /limits/);
  assert.equal(many.position, -1);
});
test('empty table remains complete; unsafe edits are rejected', () => {
  assert.deepEqual(snapshotCursor(fixture([])).rows, []);
  const table = {columns:['value'], rows:[[{type:'integer',value:'9223372036854775808'}]]};
  assert.throws(() => validateTable(table), /out-of-range/);
  table.rows[0][0] = {type:'float',value:Infinity};
  assert.throws(() => validateTable(table), /Unsupported/);
  table.rows[0][0] = {type:'string',value:'x'.repeat(8193)};
  assert.throws(() => validateTable(table), /Unsupported/);
});
test('replacement is constructed independently and closes only itself on build failure', () => {
  let closed = false;
  const cursor = { addRow: {overload: () => ({call: () => { throw new Error('allocation'); }})}, close: () => { closed = true; } };
  const Java = {use: name => ({$new: () => name.includes('MatrixCursor') ? cursor : 'text'}), array: (_, values) => values};
  assert.throws(() => buildCursor(Java, {columns:['value'],rows:[[{type:'string',value:'text'}]]}, value => value), /allocation/);
  assert.equal(closed, true);
});
