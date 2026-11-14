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
  return { Java, method, monitor, hook, messages, flush: () => flush(), calls: () => calls,
    settle: () => { while (pending.length) pending.shift()(); } };
}

test('suppression is nested, local to the current thread and restored on error', () => {
  const f = fixture();
  f.monitor.configure([f.hook], 0);
  f.settle();
  const previous = global.Process;
  let thread = 1;
  global.Process = { getCurrentThreadId: () => thread };
  const call = text => f.method.implementation(text);
  const error = new Error('inspection failed');
  try {
    assert.throws(() => f.monitor.withoutRecording(() => {
      assert.equal(call('outer'), 'outer');
      f.monitor.withoutRecording(() => assert.equal(call('inner'), 'inner'));
      assert.equal(call('outer again'), 'outer again');
      thread = 2;
      assert.equal(call('other thread'), 'other thread');
      thread = 1;
      throw error;
    }), thrown => thrown === error);
    assert.equal(call('after'), 'after');
    assert.deepEqual(f.monitor.stop().events.map(event => event.arguments[0].value), ['other thread', 'after']);
  } finally {
    global.Process = previous;
  }
});

test('Intent parcelable getter observes the returned type without traversing the object', () => {
  const result = { $className: 'android.content.Intent', getExtras() { assert.fail('must stay opaque'); } };
  const f = fixture(key => key === 'next' ? result : null, 'getParcelableExtra');
  f.monitor.configure([Object.assign(f.hook, { class: 'android.content.Intent' })], 0);
  f.settle();
  assert.equal(f.method.implementation('next'), result);
  assert.equal(f.method.implementation('missing'), null);
  const [present, missing] = f.monitor.stop().events;
  assert.deepEqual(present.result, { type: 'android.content.Intent', opaque: true });
  assert.equal(missing.result.value, null);

  const typed = fixture(() => result, 'getParcelableExtra');
  typed.Java.cast = value => value;
  typed.monitor.configure([Object.assign(typed.hook, {
    class: 'android.content.Intent', args: ['java.lang.String', 'java.lang.Class'],
  })], 0);
  typed.settle();
  const expected = { $className: 'java.lang.Class', getName: () => 'android.content.Intent' };
  assert.equal(typed.method.implementation('next', expected), result);
  const [event] = typed.monitor.stop().events;
  assert.deepEqual(event.arguments[1], {
    type: 'java.lang.Class', value: 'android.content.Intent', truncated: false,
  });
  assert.deepEqual(event.result, { type: 'android.content.Intent', opaque: true });
});

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

test('File.renameTo records source, destination and the original boolean result', () => {
  const f = fixture(() => false, 'renameTo');
  f.hook.class = 'java.io.File';
  f.hook.args = ['java.io.File'];
  f.method.returnType.className = 'boolean';
  f.monitor.configure([f.hook], 0);
  f.settle();
  const source = { $className: 'java.io.File', getPath: () => 'relative/source' };
  const target = { $className: 'app.CustomFile', getPath() { assert.fail('unexpected app code'); } };
  assert.equal(f.method.implementation.call(source, target), false);
  f.flush();
  const [event] = f.messages.at(-1).events;
  assert.equal(event.sourcePath.value, 'relative/source');
  assert.equal(event.arguments[0].opaque, true);
  assert.equal(event.result.value, false);
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

test('incoming provider call records caller, provider and standard query arguments only', () => {
  const f = fixture(() => null, 'query');
  f.Java.use = clazz => clazz === 'android.os.Binder' ? { getCallingUid: () => 10123 }
    : { query: { overload: () => f.method } };
  Object.assign(f.hook, { class: 'android.content.ContentProvider$Transport', profile: 'provider-inbound',
    args: ['android.content.AttributionSource', 'android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle',
      'android.os.ICancellationSignal'] });
  f.monitor.configure([f.hook], 0);
  f.settle();
  const transport = { this$0: { value: { getClass: () => ({ getName: () => 'app.NotesProvider' }) } } };
  const source = { $className: 'android.content.AttributionSource', getPackageName: () => 'app.caller' };
  const uri = { $className: 'android.net.Uri$StringUri', toString: () => 'content://app/notes' };
  const read = [];
  const bundle = { $className: 'android.os.Bundle',
    getString(key) { read.push(key); return key.endsWith('selection') ? '1=1 --' : null; },
    getStringArray(key) { read.push(key); return ['a', null]; },
    keySet() { assert.fail('must not enumerate caller keys'); } };
  f.method.implementation.call(transport, source, uri, ['title'], bundle, null);
  const subclass = { $className: 'app.Bundle', getString() { assert.fail('must stay opaque'); } };
  f.method.implementation.call(transport, null, uri, null, subclass, null);
  const [event, other] = f.monitor.stop().events;
  assert.equal(event.provider.value, 'app.NotesProvider');
  assert.deepEqual(event.callingUid, { type: 'int', value: 10123 });
  assert.equal(event.arguments[0].value, 'app.caller');
  assert.equal(event.arguments[1].value, 'content://app/notes');
  assert.deepEqual(event.arguments[2].items.map(item => item.value), ['title']);
  const query = event.arguments[3].queryArguments;
  assert.equal(query.selection.value, '1=1 --');
  assert.deepEqual(query.selectionArgs.items.map(item => item.value), ['a', null]);
  assert.equal(query.sortOrder.value, null);
  assert.equal(read.length, 3);
  assert.equal(other.arguments[0].value, null);
  assert.deepEqual(other.arguments[3], { type: 'android.os.Bundle', opaque: true });
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

test('resolver read stream folds a delegated typed open but keeps explicit typed calls', () => {
  const messages = [];
  const uri = { $className: 'android.net.Uri$StringUri', toString: () => 'content://example/item' };
  const typed = {
    handle: 'typed', implementation: null, returnType: { className: 'android.content.res.AssetFileDescriptor' },
    apply() { return {}; },
  };
  const stream = {
    handle: 'stream', implementation: null, returnType: { className: 'java.io.InputStream' },
    apply(receiver, [uri]) { return typed.implementation.call(receiver, uri, '*/*', null, null); },
  };
  const Java = {
    perform: fn => fn(),
    use: () => ({
      openInputStream: { overload: () => stream },
      openTypedAssetFileDescriptor: { overload: () => typed },
    }),
  };
  const monitor = createMonitor(Java, message => messages.push(message), () => {});
  const base = { class: 'android.content.ContentResolver', profile: 'content-provider',
    profileName: 'Content Provider', captureArguments: true, captureReturn: true };
  monitor.configure([
    { ...base, method: 'openInputStream', args: ['android.net.Uri'], index: 0 },
    { ...base, method: 'openTypedAssetFileDescriptor',
      args: ['android.net.Uri', 'java.lang.String', 'android.os.Bundle', 'android.os.CancellationSignal'], index: 1 },
  ], 0);

  const receiver = {};
  stream.implementation.call(receiver, uri);
  typed.implementation.call(receiver, uri, 'text/plain', null, null);
  assert.deepEqual(monitor.stop().events.map(event => event.method),
    ['openInputStream', 'openTypedAssetFileDescriptor']);
});

test('WebView observations survive unrelated hook edits and distinguish colliding identities', () => {
  const messages = [];
  const exception = { $className: 'java.lang.IllegalArgumentException' };
  const implementation = { getName: () => 'app.Settings', getClassLoader: () => null };
  const makeMethod = (name, apply) => ({
    handle: name, implementation: null, apply, returnType: { className: 'void' },
  });
  const getter = makeMethod('getSettings', view => view.settings);
  const load = makeMethod('loadUrl', () => undefined);
  const setter = makeMethod('setJavaScriptEnabled', (_, [value]) => {
    if (value === 'invalid') throw exception;
  });
  const read = makeMethod('getDataString', () => 'data');
  const Java = {
    perform: fn => fn(),
    backtrace: () => ({ frames: [{ signature: 'app.Activity.open()' }] }),
    use: clazz => {
      if (clazz === 'java.lang.System') return { identityHashCode: () => 1 };
      if (clazz === 'java.lang.ref.WeakReference') return { $new: object => ({ get: () => object }) };
      if (clazz === 'android.webkit.WebView') return {
        getSettings: { overload: () => getter }, loadUrl: { overload: () => load },
      };
      if (clazz === 'android.content.Intent') return { getDataString: { overload: () => read } };
      assert.equal(clazz, 'app.Settings');
      return { setJavaScriptEnabled: { overload: () => setter } };
    },
  };
  const monitor = createMonitor(Java, message => messages.push(structuredClone(message)), () => {});
  const base = { profile: 'webview', profileName: 'WebView', captureArguments: true, captureReturn: false };
  const webHooks = [
    { ...base, class: 'android.webkit.WebView', method: 'getSettings', args: [], index: 0 },
    { ...base, class: 'android.webkit.WebView', method: 'loadUrl', args: ['java.lang.String'], index: 1 },
    { ...base, class: 'android.webkit.WebSettings', method: 'setJavaScriptEnabled', args: ['boolean'], index: 2 },
  ];
  const intent = { ...base, profile: 'intent', profileName: 'Intent', index: 0,
    class: 'android.content.Intent', method: 'getDataString', args: [] };
  monitor.configure([...webHooks, intent], 0);
  assert.equal(messages.at(-1).statuses[2].state, 'Pending');
  function view() {
    return { $isSameObject(other) { return this === other; },
      settings: { getClass: () => implementation, $isSameObject(other) { return this === other; } } };
  }
  const a = view(), b = view();
  load.implementation.call(a, 'first');
  getter.implementation.call(a);
  getter.implementation.call(b);
  assert.equal(messages.at(-1).statuses[2].state, 'Active');
  setter.implementation.call(a.settings, true);
  setter.implementation.call(b.settings, false);
  load.implementation.call(a, 'a');
  assert.throws(() => setter.implementation.call(a.settings, 'invalid'), error => error === exception);
  load.implementation.call(a, 'a after failed change');
  load.implementation.call(b, 'b');
  monitor.configure([...webHooks, { ...intent, captureStack: true }], 1);
  assert.equal(messages.at(-1).revision, 1);
  assert.equal(messages.at(-1).statuses[2].state, 'Active');
  load.implementation.call(a, 'a after reconfigure');
  read.implementation.call({});
  setter.implementation.call(a.settings, false);
  load.implementation.call(a, 'a after successful change');
  monitor.configure(webHooks.map(spec => spec.index === 2 ? { ...spec, captureArguments: false } : spec), 2);
  assert.equal(messages.at(-1).statuses[2].state, 'Pending');
  getter.implementation.call(a);
  setter.implementation.call(a.settings, true);
  load.implementation.call(a, 'a without setting capture');

  const captured = monitor.stop().events;
  assert.deepEqual(captured.find(event => event.method === 'getDataString').stack, ['app.Activity.open()']);
  const events = captured.filter(event => event.method === 'loadUrl');
  assert.deepEqual(events.map(event => event.webViewId), [1, 1, 1, 2, 1, 1, 3]);
  assert.deepEqual(events.map(event => event.webViewSettings.setJavaScriptEnabled),
    [undefined, true, true, false, true, false, undefined]);
});

test('process capture bounds argument vectors and leaves application lists opaque', () => {
  const process = {};
  const f = fixture(() => process, 'start');
  f.hook.class = 'java.lang.ProcessBuilder';
  f.hook.args = [];
  f.hook.profile = 'process-execution';
  f.method.returnType.className = 'java.lang.Process';
  f.monitor.configure([f.hook], 0);
  f.settle();

  const args = ['/bin/echo', 'a single argument', ...Array(35).fill('x'.repeat(600))];
  const list = { $className: 'java.util.ArrayList', size: () => args.length, get: i => args[i] };
  const custom = { $className: 'app.CommandList',
    size() { assert.fail('unexpected app code'); }, get() { assert.fail('unexpected app code'); } };
  const directory = { $className: 'java.io.File', getPath: () => 'relative' };
  assert.equal(f.method.implementation.call({command: () => list, directory: () => directory}), process);
  assert.equal(f.method.implementation.call({command: () => custom, directory: () => null}), process);
  const [known, opaque] = f.monitor.stop().events;
  assert.equal(known.workingDirectory.value, 'relative');
  assert.equal(known.processCommand.count, 37);
  assert.equal(known.processCommand.items.length, 32);
  assert.equal(known.processCommand.items[1].value, 'a single argument');
  assert.equal(known.processCommand.items[2].value.length, 512);
  assert.equal(known.processCommand.items[2].truncated, true);
  assert.deepEqual(opaque.processCommand, { type: '[Ljava.lang.String;', opaque: true });
  assert.equal(opaque.workingDirectory.value, null);
});

test('in-memory DEX capture reads only remaining sizes from a bounded buffer list', () => {
  const clazz = 'dalvik.system.InMemoryDexClassLoader';
  const bufferType = 'java.nio.ByteBuffer';
  const arrayType = '[Ljava.nio.ByteBuffer;';
  const parent = {};
  const buffers = Array.from({ length: 10 }, (_, index) => ({
    remaining: () => 100 + index,
    get() { assert.fail('unexpected buffer read'); },
    position() { assert.fail('unexpected position access'); },
  }));
  const method = { handle: 'memory-dex', implementation: null, returnType: { className: 'void' },
    apply(_, args) { assert.equal(args[0], buffers); assert.equal(args[1], parent); } };
  const bufferClass = {};
  const Java = {
    perform: fn => fn(),
    use(name) {
      if (name === 'java.nio.Buffer') return bufferClass;
      assert.equal(name, clazz);
      return { $init: { overload: () => method } };
    },
    cast(object, type) { assert.equal(type, bufferClass); return object; },
  };
  const monitor = createMonitor(Java, () => {}, () => {});
  monitor.configure([{
    class: clazz, method: '$init', args: [arrayType, 'java.lang.ClassLoader'],
    profile: 'dynamic-code-loading', profileName: 'Dynamic Code Loading', index: 0, captureArguments: true,
  }], 0);
  method.implementation(buffers, parent);
  const [event] = monitor.stop().events;
  assert.equal(event.arguments[0].count, 10);
  assert.deepEqual(event.arguments[0].items, Array.from({ length: 8 }, (_, index) =>
    ({ type: bufferType, remainingBytes: 100 + index })));
  assert.equal(event.arguments[1].opaque, true);
});
