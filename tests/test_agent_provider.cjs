const test = require('node:test');
const assert = require('node:assert/strict');
const { createProviderInterceptor } = require('../agent/provider_intercept.js');
global.Process = { id: 7, getCurrentThreadId: () => 1 };
const uri = value => ({ $className: 'android.net.Uri$StringUri', toString: () => value });

function fixture(original = () => null, missingTransport = false, blocking = true, methodName = 'query') {
  let implementation = null, wait, claimed = false;
  const events = [], calls = [];
  const types = ['android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String'];
  const method = {
    handle: 'query', argumentTypes: types.map(className => ({ className })),
    returnType: { className: 'java.lang.Object' },
    get implementation() { return implementation; },
    set implementation(value) { implementation = value; },
    apply(self, args) { calls.push(Array.from(args)); return original.apply(self, args); },
  };
  const lock = { wait() { wait(); }, notifyAll() {} };
  const Java = {
    perform: fn => fn(), performNow: fn => fn(), synchronized: (_, fn) => fn(),
    use(name) {
      if (missingTransport && name === 'android.content.ContentProvider$Transport')
        throw new Error('Transport unavailable');
      if (name === 'java.lang.Object') return { $new: () => lock };
      if (name === 'android.net.Uri') return { parse: uri };
      if (name === 'android.os.OperationCanceledException') return { $new: message => new Error(message) };
      return { [methodName]: { overloads: [method] } };
    },
    array: (_, value) => value,
    cast: value => value,
  };
  const engine = createProviderInterceptor(Java, event => events.push(event), {
    inspect: fn => fn(), stamp: () => ({ time: 1 }), begin: () => 1, end: () => {},
    blocking: () => blocking,
    claim() { if (!blocking || claimed) return false; claimed = true; return true; },
    release() { claimed = false; },
  });
  return { engine, method, events, calls, setWait: fn => { wait = fn; } };
}
test('query Bundle completeness requires only supported keys with matching types', async () => {
  for (const extra of [null, 'android:query-arg-limit']) {
    const f = fixture(() => null, false, false);
    f.method.argumentTypes = ['android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle']
      .map(className => ({ className }));
    const keys = ['android:query-arg-sql-selection'];
    if (extra) keys.push(extra);
    const bundle = {
      isParcelled: () => false, getString: key => key.endsWith('selection') ? 'title = ?' : null,
      getStringArray: () => null, get: () => ({ $className: 'java.lang.String' }),
      keySet: () => ({ size: () => keys.length, iterator: () => {
        let i = 0; return { hasNext: () => i < keys.length, next: () => keys[i++] };
      } }),
    };
    await f.engine.configure(true, false);
    f.method.implementation(uri('content://test/notes'), null, bundle);
    assert.equal(f.events[0].queryArgumentsComplete, extra === null);
  }
});
test('opted-in preview records returned rows without a hold or replacing the Cursor', async () => {
  let position = -1;
  const cursor = {
    $className: 'demo.Cursor', getPosition: () => position, getColumnNames: () => ['title'],
    moveToPosition: row => { position = row; return row === 0; },
    getType: () => 3, getString: () => 'first',
  };
  const f = fixture(() => cursor, false, false);
  f.method.returnType.className = 'android.database.Cursor';
  await f.engine.configure(true, false);
  const hook = f.method.implementation;
  const query = () => f.method.implementation(uri('content://test/notes'), null, null, null, null);
  assert.equal(query(), cursor);
  assert.equal(f.events.at(-1).cursorPreview, undefined);
  f.events.length = 0;
  f.engine.setCursorPreviews(true);
  assert.equal(query(), cursor);
  assert.equal(position, -1);
  assert.deepEqual(f.events.map(event => event.noxenEvent), ['provider_request', 'provider_result']);
  assert.deepEqual(f.events.at(-1).cursorPreview, {
    columns: ['title'], rows: [[{ type: 'string', value: 'first' }]], complete: true,
  });
  cursor.getString = () => { throw new Error('Read failed'); };
  assert.equal(query(), cursor);
  assert.equal(position, -1);
  assert.match(f.events.at(-1).cursorPreviewError, /Read failed/);
  f.engine.setCursorPreviews(false);
  assert.equal(query(), cursor);
  assert.equal(f.events.at(-1).cursorPreviewError, undefined);
  assert.equal(f.method.implementation, hook);
});
test('missing incoming API keeps outgoing provider hooks active', async () => {
  const f = fixture(() => null, true);
  const report = await f.engine.configure(true, true);
  assert.deepEqual(report.enabled, { outgoing: true, incoming: false });
  assert.equal(report.hooks.some(hook => hook.direction === 'incoming' && hook.state === 'Unavailable'), true);
  assert.equal(typeof f.method.implementation, 'function');
});
test('insert records the returned URI and preserves the result object', async () => {
  for (const result of [uri('content://test/notes/3'), null]) {
    const f = fixture(() => result, false, false, 'insert');
    f.method.returnType.className = 'android.net.Uri';
    await f.engine.configure(true, false);
    assert.equal(f.method.implementation(uri('content://test/notes'), null, null, null, null), result);
    assert.deepEqual(f.events.at(-1).result,
      { type: 'android.net.Uri', value: result === null ? null : 'content://test/notes/3' });
  }
});
test('getType response supports changed strings, empty strings and null without rerunning the call', async () => {
  for (const [original, edited] of [['text/plain', 'image/png'], ['text/plain', null],
                                     [null, 'text/plain'], ['text/plain', ''], [null, null]]) {
    const f = fixture(() => original, false, true, 'getType');
    f.method.returnType.className = 'java.lang.String';
    await f.engine.configure(true, false);
    f.setWait(() => {
      const event = f.events.at(-1);
      if (event.phase === 'request') {
        f.engine.resolve(event.decisionId, 'forward', null);
      } else {
        assert.deepEqual(event.editableResult, { value: original });
        assert.throws(() => f.engine.resolve(event.decisionId, 'forward', { value: 42 }), /Response requires/);
        assert.throws(() => f.engine.resolve(event.decisionId, 'inspect', null), /Cursor/);
        f.engine.resolve(event.decisionId, 'forward', { value: edited });
      }
    });
    assert.equal(f.method.implementation(uri('content://test/notes'), null, null, null, null), edited);
    assert.equal(f.calls.length, 1);
    const update = f.events.find(event => event.phase === 'response' && event.noxenEvent === 'provider_update');
    assert.equal(update.state, original === edited ? 'forwarded' : 'modified_forwarded');
    assert.equal(f.events.at(-1).result.value, original);
    if (original !== edited) assert.equal(update.sentResult.value, edited);
  }
});
test('provider edits validate before wakeup and preserve original result', async () => {
  const result = {};
  const f = fixture(() => result);
  await f.engine.configure(true, false);
  f.setWait(() => {
    const request = f.events[0];
    assert.equal(f.engine.resolve('stale', 'forward', {}), false);
    assert.throws(() => f.engine.resolve(request.id, 'forward', { uri: 4 }), /keys/);
    assert.equal(f.calls.length, 0);
    assert.equal(f.engine.resolve(request.id, 'forward', {
      ...request.arguments, selectionArgs: ['second'],
    }), true);
  });
  const input = uri('content://test/notes');
  assert.equal(f.method.implementation(input, null, 'title = ?', ['first'], null), result);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0][0], input);
  assert.deepEqual(f.calls[0][3], ['second']);
  assert.equal(f.events[1].state, 'modified_forwarded');
  assert.equal(f.events[2].state, 'returned');
});
test('drop skips provider and next call proceeds after disabling', async () => {
  const f = fixture();
  await f.engine.configure(true, false);
  f.setWait(() => f.engine.resolve(f.events.at(-1).id, 'drop', null));
  assert.throws(() => f.method.implementation(uri('content://test/notes'), null, null, null, null), /Blocked by noxen/);
  assert.equal(f.calls.length, 0);
  await f.engine.configure(false, false);
  f.method.implementation(uri('content://test/notes'), null, null, null, null);
  assert.equal(f.calls.length, 1);
});
test('forward preserves the original exception', async () => {
  const error = new Error('Permission denied');
  const f = fixture(() => { throw error; });
  await f.engine.configure(true, false);
  f.setWait(() => f.engine.resolve(f.events[0].id, 'forward', null));
  assert.throws(() => f.method.implementation(uri('content://test/notes'), null, null, null, null), x => x === error);
  assert.equal(f.events.at(-1).state, 'exception');
});

test('Cursor response has a distinct decision and does not read until requested', async () => {
  let reads = 0, position = -1, closed = false;
  const cursor = { $className: 'demo.Cursor',
    getPosition: () => position, getCount: () => { reads++; return 1; },
    getColumnNames: () => ['_display_name'], moveToPosition: row => { position = row; return row === 0; },
    getType: () => 3, getString: () => 'report.txt', close: () => { closed = true; } };
  const f = fixture(() => cursor);
  f.method.returnType.className = 'android.database.Cursor';
  await f.engine.configure(true, false);
  let phase = 0;
  f.setWait(() => {
    if (phase++ === 0) {
      assert.equal(reads, 0);
      f.engine.resolve(f.events[0].decisionId, 'forward', null);
    } else if (phase === 2) {
      const response = f.events.at(-1);
      assert.equal(response.phase, 'response');
      assert.equal(reads, 0);
      assert.equal(f.engine.resolve(f.events[0].decisionId, 'drop', null), false);
      f.engine.resolve(response.decisionId, 'inspect', null);
    } else {
      assert.equal(position, -1);
      assert.equal(reads, 1);
      const response = f.events.at(-1);
      assert.equal(response.cursor.rows[0][0].value, 'report.txt');
      assert.throws(() => f.engine.resolve(response.decisionId, 'forward', { columns: [], rows: [] }), /Cursor table/);
      f.engine.resolve(response.decisionId, 'forward', null);
    }
  });
  assert.equal(f.method.implementation(uri('content://test/notes'), null, null, null, null), cursor);
  assert.equal(f.calls.length, 1);
  assert.equal(closed, false);
  const update = f.events.find(event => event.noxenEvent === 'provider_update' && event.phase === 'response');
  assert.equal(update.state, 'forwarded');
  assert.equal('sentCursor' in update, false);
});
test('automatic previews make complete held responses editable and keep partial responses read-only', async () => {
  for (const count of [1, 101]) {
    let position = -1;
    const cursor = { $className: 'demo.Cursor', getPosition: () => position,
      getColumnNames: () => ['title'],
      moveToPosition: row => { position = row; return row >= 0 && row < count; },
      getType: () => 3, getString: () => 'first', close: () => {} };
    const f = fixture(() => cursor);
    f.method.returnType.className = 'android.database.Cursor';
    await f.engine.configure(true, false, true);
    let response;
    f.setWait(() => {
      const event = f.events.at(-1);
      if (event.phase === 'request') {
        f.engine.resolve(event.decisionId, 'forward', null);
      } else {
        response = event;
        assert.equal(position, -1);
        if (count === 1) {
          assert.equal(event.cursor.rows[0][0].value, 'first');
          assert.equal(f.engine.resolve(event.decisionId, 'forward', event.cursor), true);
        } else {
          assert.equal(event.cursor, undefined);
          assert.equal(event.cursorPreview.complete, false);
          assert.throws(() => f.engine.resolve(event.decisionId, 'forward', {
            columns: ['title'], rows: [] }), /Read Cursor/);
          f.engine.resolve(event.decisionId, 'forward', null);
        }
      }
    });
    assert.equal(f.method.implementation(uri('content://test/notes'), null, null, null, null), cursor);
    assert.equal(f.calls.length, 1);
    assert.equal(response.state, 'held');
  }
});
