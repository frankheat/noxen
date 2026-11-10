const test = require('node:test');
const assert = require('node:assert/strict');
const { createMonitor } = require('../agent/monitor.js');
global.Process = { getCurrentThreadId: () => 42 };

function fixture(original = x => x) {
  const messages = [], pending = [];
  let flush, calls = 0, impl = null;
  const method = { handle: '0x123', returnType: { className: 'java.lang.String' },
    apply(self, args) { calls++; return original.apply(self, args); },
    get implementation() { return impl; },
    set implementation(fn) { impl = fn; } };
  const Java = { perform: fn => pending.push(fn), backtrace: () => ({ frames: [] }),
    use: clazz => { if (clazz === 'Missing') throw new Error('Class not found'); return { run: { overload: () => method } }; } };
  const monitor = createMonitor(Java, m => messages.push(m), fn => { flush = fn; });
  const hook = { class: 'Example', method: 'run', args: ['java.lang.String'], profile: 'a',
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
  for (let i = 0; i < 200; i++) f.method.implementation('x'.repeat(3000));
  f.flush(); const batch = f.messages.at(-1);
  assert.equal(f.calls(), 200); assert.equal(batch.dropped, 72); assert.equal(batch.events.length, 32);
  assert.equal(batch.events[0].arguments[0].truncated, true);
  assert.equal(batch.events[0].arguments[0].value.length, 2048);
});

test('capture failures cannot prevent app execution', () => {
  const f = fixture(); f.hook.captureStack = true;
  f.monitor.configure([f.hook], 0); f.settle();
  const bad = { toString() { throw new Error('bad capture'); } };
  assert.equal(f.method.implementation(bad), bad);
  assert.equal(f.calls(), 1);
});
