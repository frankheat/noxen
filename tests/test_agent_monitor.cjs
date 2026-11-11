const test = require('node:test');
const assert = require('node:assert/strict');
const { createMonitor } = require('../agent/monitor.js');
global.Process = { getCurrentThreadId: () => 42 };

function fixture(original = x => x, methodName = 'run') {
  const messages = [], pending = [];
  let flush, calls = 0, impl = null;
  const method = { handle: '0x123', returnType: { className: 'java.lang.String' },
    apply(self, args) { calls++; return original.apply(self, args); },
    get implementation() { return impl; },
    set implementation(fn) { impl = fn; } };
  const Java = { perform: fn => pending.push(fn), backtrace: () => ({ frames: [] }),
    use: clazz => { if (clazz === 'Missing') throw new Error('Class not found'); return { [methodName]: { overload: () => method } }; } };
  const monitor = createMonitor(Java, m => messages.push(m), fn => { flush = fn; });
  const hook = { class: 'Example', method: methodName, args: ['java.lang.String'], profile: 'a',
    profileName: 'A', index: 0, captureArguments: true, captureReturn: true, captureStack: false };
  return { method, monitor, hook, messages, flush: () => flush(), calls: () => calls,
    settle: () => { while (pending.length) pending.shift()(); } };
}

test('preserves exact return, this, args and exception; unknown objects are opaque', () => {
  const exception = { $className: 'TestException' };
  const f = fixture(function (arg) { assert.equal(this.marker, 3); if (arg === 'fail') throw exception; return arg; });
  f.monitor.configure([f.hook], 0); f.settle();
  assert.equal(f.method.implementation.call({marker: 3}, 'ok'), 'ok');
  assert.throws(() => f.method.implementation.call({marker: 3}, 'fail'), e => e === exception);
  assert.equal(f.calls(), 2); f.flush();
  assert.deepEqual(f.messages.at(-1).events.map(e => e.outcome), ['returned', 'exception']);
  const opaque = { toString() { throw new Error('must not stringify'); } };
  f.hook.args = ['java.lang.Object'];
  f.monitor.configure([f.hook], 1); f.settle();
  assert.equal(f.method.implementation.call({marker: 3}, opaque), opaque);
  f.flush();
  assert.equal(f.messages.at(-1).events[0].arguments[0].opaque, true);
});

test('profiles share one wrapper, disabling preserves original calls, stale updates ignored', () => {
  const f = fixture();
  f.monitor.configure([f.hook], 0);
  f.monitor.configure([f.hook, {...f.hook, profile: 'b', profileName: 'B'}], 1); f.settle();
  f.method.implementation('x'); f.flush();
  assert.deepEqual(f.messages.at(-1).events[0].profiles, ['A', 'B']);
  assert.equal(f.calls(), 1);
  f.monitor.configure([], 2); f.settle();
  const count = f.messages.length;
  assert.equal(f.method.implementation('y'), 'y'); f.flush();
  assert.equal(f.messages.length, count);
});

test('does not replace existing hooks; missing classes reported separately', () => {
  const f = fixture(); const external = () => 123; f.method.implementation = external;
  f.monitor.configure([f.hook, {...f.hook, class: 'Missing', index: 1}], 0); f.settle();
  assert.equal(f.method.implementation, external);
  assert.deepEqual(f.messages.at(-1).statuses.map(s => s.state), ['Error', 'Not found']);
});

test('queue is bounded and reports dropped calls; strings have explicit truncation', () => {
  const f = fixture(); f.monitor.configure([f.hook], 0); f.settle();
  const value = 'x'.repeat(3000);
  for (let i = 0; i < 600; i++) f.method.implementation(value);
  f.flush(); const batch = f.messages.at(-1);
  assert.equal(f.calls(), 600); assert.equal(batch.dropped, 88); assert.equal(batch.events.length, 32);
  assert.equal(batch.events[0].arguments[0].truncated, true);
  assert.equal(batch.events[0].arguments[0].value.length, 2048);
  for (let i = 0; i < 16; i++) f.flush();
  const batches = f.messages.filter(message => message.noxenEvent === 'monitor_batch');
  assert.equal(batches.length, 16);
  assert.ok(batches.every(message => message.events.length === 32));
  assert.equal(batches.reduce((total, message) => total + message.dropped, 0), 88);
});

test('stopping returns the remaining events and leaves hooks passive', () => {
  const f = fixture();
  f.monitor.configure([f.hook], 0);
  f.settle();
  for (let i = 0; i < 520; i++) f.method.implementation('x');
  f.flush();
  const final = f.monitor.stop();
  assert.equal(final.events.length, 480);
  assert.equal(final.dropped, 0);
  assert.equal(final.incomplete, false);
  const messageCount = f.messages.length;
  assert.equal(f.monitor.configure([f.hook], 1), false);
  assert.equal(f.method.implementation('still works'), 'still works');
  f.flush();
  assert.equal(f.messages.length, messageCount);
  assert.equal(f.monitor.stop().events.length, 0);
});

test('capture failures cannot prevent app execution', () => {
  const f = fixture(); f.hook.captureStack = true;
  f.monitor.configure([f.hook], 0); f.settle();
  const bad = { toString() { throw new Error('bad capture'); } };
  assert.equal(f.method.implementation(bad), bad);
  assert.equal(f.calls(), 1);
});

test('file capture reads the stored path only from the framework File class', () => {
  const f = fixture(() => undefined);
  f.hook.args = ['java.io.File'];
  f.monitor.configure([f.hook], 0);
  f.settle();
  const file = { $className: 'java.io.File', getPath: () => 'relative/report.txt' };
  let subclassReads = 0;
  const subclass = { $className: 'app.CustomFile', getPath() { subclassReads++; return 'other'; } };
  f.method.implementation(file);
  f.method.implementation(subclass);
  f.flush();
  const [plain, opaque] = f.messages.at(-1).events;
  assert.equal(plain.arguments[0].value, 'relative/report.txt');
  assert.equal(opaque.arguments[0].opaque, true);
  assert.equal(subclassReads, 0);
});

test('URL preparation reads only selected stored fields', () => {
  const f = fixture(() => null, 'openConnection');
  f.hook.class = 'java.net.URL';
  f.hook.args = [];
  f.monitor.configure([f.hook], 0);
  f.settle();
  const url = {
    getProtocol: () => 'https',
    getHost: () => '[::1]',
    getPort: () => -1,
    getPath: () => '/report',
    getDefaultPort() { assert.fail('URL handler must not be called'); },
    toExternalForm() { assert.fail('URL handler must not be called'); },
    getQuery() { assert.fail('query must not be captured'); },
  };
  assert.equal(f.method.implementation.call(url), null);
  f.flush();
  assert.equal(f.messages.at(-1).events[0].destination.value, 'https://[::1]/report');
});

test('Cipher init captures transformation and mode without inspecting key material', () => {
  let originalKey, reads = 0;
  const f = fixture((mode, key) => { originalKey = key; }, 'init');
  f.hook.class = 'javax.crypto.Cipher';
  f.hook.args = ['int', 'java.security.Key'];
  f.hook.captureReturn = false;
  f.monitor.configure([f.hook], 0);
  f.settle();
  const key = {
    $className: 'app.CustomKey',
    getEncoded() { reads++; return [1, 2, 3]; },
    toString() { reads++; return 'sensitive'; },
  };
  const cipher = { getAlgorithm: () => 'AES/GCM/NoPadding' };
  f.method.implementation.call(cipher, 1, key);
  f.flush();
  const event = f.messages.at(-1).events[0];
  assert.equal(originalKey, key);
  assert.equal(reads, 0);
  assert.equal(event.transformation.value, 'AES/GCM/NoPadding');
  assert.equal(event.arguments[0].value, 1);
  assert.deepEqual(event.arguments[1], { type: 'app.CustomKey', opaque: true });
});

test('SQLite bindings are bounded and leave custom objects and the original array untouched', () => {
  let originalArgs, stringifications = 0;
  const f = fixture((_, args) => { originalArgs = args; }, 'execSQL');
  f.hook.class = 'android.database.sqlite.SQLiteDatabase';
  f.hook.args = ['java.lang.String', '[Ljava.lang.Object;'];
  f.monitor.configure([f.hook], 0);
  f.settle();
  const unknown = { $className: 'app.Custom', toString() { stringifications++; return 'unexpected'; } };
  const bindings = ['x'.repeat(600), unknown, ...Array(16).fill(null)];
  f.method.implementation('SELECT ?', bindings);
  f.flush();
  const captured = f.messages.at(-1).events[0].arguments[1];
  assert.equal(originalArgs, bindings);
  assert.equal(stringifications, 0);
  assert.equal(captured.count, 18);
  assert.equal(captured.items.length, 16);
  assert.equal(captured.items[0].value.length, 512);
  assert.equal(captured.items[0].truncated, true);
  assert.equal(captured.items[1].opaque, true);
});

test('resolver delegation keeps the outer call and still reports a custom inner hook', () => {
  const messages = [];
  let flush, calls = 0;
  const short = {
    handle: 'short', implementation: null, returnType: { className: 'android.os.ParcelFileDescriptor' },
    apply(receiver, [uri, mode]) { return long.implementation.call(receiver, uri, mode, null); },
  };
  const long = {
    handle: 'long', implementation: null, returnType: short.returnType,
    apply() { calls++; return {}; },
  };
  const Java = {
    perform: fn => fn(),
    use: () => ({ openFileDescriptor: { overload: (...args) => args.length === 2 ? short : long } }),
  };
  const monitor = createMonitor(Java, m => messages.push(m), fn => { flush = fn; });
  const outer = { class: 'android.content.ContentResolver', method: 'openFileDescriptor',
    args: ['android.net.Uri', 'java.lang.String'], profile: 'content-provider', profileName: 'Content Provider',
    index: 0, captureArguments: true, captureReturn: true };
  const inner = { ...outer, args: [...outer.args, 'android.os.CancellationSignal'], index: 1 };
  monitor.configure([outer, inner, { ...inner, profile: 'custom', profileName: 'Custom' }], 0);
  const uri = { $className: 'android.net.Uri$StringUri', toString: () => 'content://example/item' };
  short.implementation.call({}, uri, 'r');
  flush();
  const events = messages.at(-1).events;
  assert.equal(calls, 1);
  assert.deepEqual(events.map(event => event.profiles), [['Custom'], ['Content Provider']]);
  assert.equal(events[1].arguments[0].value, 'content://example/item');
  assert.equal(events[1].result.opaque, true);

  monitor.configure([inner], 1);
  const unknown = { $className: 'example.CustomUri', toString() { assert.fail('unexpected stringification'); } };
  long.implementation.call({}, unknown, 'r', null);
  flush();
  assert.deepEqual(messages.at(-1).events[0].arguments[0], { type: 'android.net.Uri', opaque: true });
});
