const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const agentPath = path.join(__dirname, '..', 'agent', 'script.js');
const source = fs.readFileSync(agentPath, 'utf8').replace(
  /^import Java_bridge from 'frida-java-bridge';/, 'const Java_bridge = {};'
);

function agent() {
  const messages = [];
  const context = vm.createContext({
    Java: { performNow: callback => callback(), synchronized: (_lock, callback) => callback() },
    Process: { id: 123 }, rpc: {}, send: payload => messages.push(payload),
  });
  vm.runInContext(source, context, { filename: agentPath });
  context.Script = {
    evaluate: (name, code) => vm.runInContext(code, context, { filename: name }),
  };
  return { context, messages, exports: context.rpc.exports };
}

test('extra scripts execute in the shared runtime and preserve their source filename', () => {
  const { context, messages, exports } = agent();
  assert.equal(exports.loadExtraScript('/extra/bypass.js', 'send(Java !== undefined);'), true);
  assert.equal(messages.pop(), true);
  assert.equal(exports.loadExtraScript('/extra/empty.js', ''), true);
  assert.throws(() => exports.loadExtraScript('/extra/bad.js', 'function broken('), /SyntaxError/);
  assert.throws(() => exports.loadExtraScript('/extra/fails.js', 'throw new Error("oops");'),
    error => error.stack.includes('/extra/fails.js:1') && error.message === 'oops');
  assert.equal(exports.loadExtraScript('/extra/custom.js', 'rpc.exports.custom = () => 42;'), true);
  assert.equal(context.rpc.exports.custom(), 42);
});

test('extra scripts cannot silently replace reserved RPC exports during initial execution', () => {
  for (const code of ['rpc.exports = {};', 'rpc.exports.proxy = () => {};', 'delete rpc.exports.forward;']) {
    const { exports } = agent();
    assert.throws(() => exports.loadExtraScript('/extra/conflict.js', code), /reserved noxen RPC/);
  }
});

test('intent events identify protocol and retain explicit blocking/passive decisions', () => {
  for (const state of ['blocking', 'passive', 'busy']) {
    const { context, messages } = agent();
    context.getStackTrace = () => [];
    context.dumpIntent = () => ({});
    context.beginHold = () => 'h1';
    context.endHold = () => {};
    context.lock = { wait() { context.resumeRequested = true; } };
    context.blockEnabled = state !== 'passive';
    context.waiting = state === 'busy';
    context.processIntercept('Example', 'onReceive', {}, null, null);
    const event = messages.find(payload => payload.noxenEvent === 'intent');
    assert.ok(event);
    assert.equal(event.protocolVersion, 1);
    assert.equal(event.decision.required, state === 'blocking');
    assert.equal(event.decision.id, state === 'blocking' ? 'decision-123-1' : null);
  }
});

test('missing, malformed and stale IDs cannot decide, modify or release an active hold', () => {
  for (const id of [undefined, null, '', ' ', 0, false, {}, [], 'decision-old']) {
    const { context, exports } = agent();
    let notifications = 0;
    context.waiting = true;
    context.activeDecisionId = 'decision-current';
    context.lock = { notify() { notifications++; } };
    const mods = [{ type: 'action', key: '', val: 'changed', extraType: '' }];
    assert.equal(exports.forward(id), false);
    assert.equal(exports.drop(id), false);
    assert.equal(exports.forwardWithMods(mods, id), false);
    assert.equal(exports.interceptOffWithMods(mods, id), false);
    assert.equal(exports.stageMod('action', '', 'changed', '', id), false);
    assert.equal(context.blockEnabled, true);
    assert.equal(context.resumeMode, 'forward');
    assert.equal(context.modQueue.length, 0);
    assert.equal(notifications, 0);
  }
});

test('the exact current ID still permits each decision and cannot address a later hold', () => {
  for (const operation of ['forward', 'drop', 'forwardWithMods', 'interceptOffWithMods']) {
    const { context, exports } = agent();
    let notifications = 0;
    context.waiting = true;
    context.activeIntentPresent = true;
    context.activeDecisionId = 'decision-current';
    context.lock = { notify() { notifications++; } };
    const mods = [{ type: 'action', key: '', val: 'changed', extraType: '' }];
    const call = id => operation.endsWith('WithMods')
      ? exports[operation](mods, id) : exports[operation](id);
    assert.equal(call('decision-current'), true);
    assert.equal(notifications, 1);
    assert.equal(context.resumeMode, operation === 'drop' ? 'drop' : 'forward');
    context.activeDecisionId = 'decision-next';
    context.resumeRequested = false;
    assert.equal(call('decision-current'), false);
    assert.equal(notifications, 1);
    context.waiting = false;
    assert.equal(call('decision-next'), false);
  }
});

test('explicitly disabling interception remains a global operation', () => {
  const { context, exports } = agent();
  let notifications = 0;
  context.waiting = true;
  context.activeDecisionId = 'decision-current';
  context.lock = { notify() { notifications++; } };
  exports.interceptoff();
  assert.equal(context.blockEnabled, false);
  assert.equal(notifications, 1);
  context.waiting = false;
  assert.equal(exports.interceptOffWithMods([], null), true);
});

test('decisions arriving before wait are retained, including Drop and the complete draft', () => {
  for (const operation of ['forward', 'drop', 'forwardWithMods', 'interceptOffWithMods', 'interceptoff']) {
    const { context, exports, messages } = agent();
    const mods = [{ type: 'action', key: '', val: 'changed', extraType: '' }];
    let notifications = 0;
    context.getStackTrace = () => [];
    context.dumpIntent = () => ({});
    context.endHold = () => {};
    context.lock = {
      wait() { assert.fail('an accepted decision must not wait for another notification'); },
      notify() { notifications++; },
    };
    context.beginHold = () => {
      const id = context.activeDecisionId;
      const accepted = operation.endsWith('WithMods')
        ? exports[operation](mods, id) : exports[operation](id);
      if (operation !== 'interceptoff') assert.equal(accepted, true);
      return 'hold-early';
    };
    context.applyModifications = () => {
      assert.equal(context.modQueue[0].val, 'changed');
      return { ok: true };
    };
    assert.equal(context.processIntercept('Example', 'onReceive', {}, null, null), operation === 'drop');
    assert.equal(notifications, 1);
    assert.equal(context.waiting, false);
    assert.equal(context.activeDecisionId, null);
    assert.equal(messages.some(m => typeof m === 'string' && m.includes('Blocking Error')), false);
    assert.equal(messages.some(m => m.noxenEvent === 'modification_result'), operation.endsWith('WithMods'));
  }
});

test('wakeups without a decision continue waiting instead of forwarding', () => {
  const { context, exports } = agent();
  let waits = 0;
  context.getStackTrace = () => [];
  context.dumpIntent = () => ({});
  context.beginHold = () => 'hold-wake';
  context.endHold = () => {};
  context.lock = {
    notify() {},
    wait() {
      waits++;
      assert.equal(context.waiting, true);
      if (waits < 3) assert.equal(context.resumeRequested, false);
      else assert.equal(exports.drop(context.activeDecisionId), true);
      assert.ok(waits <= 3);
    },
  };
  assert.equal(context.processIntercept('Example', 'onReceive', {}, null, null), true);
  assert.equal(waits, 3);
});

test('interruptions do not decide and the interrupt flag is restored only after the hold', () => {
  for (const operation of ['forward', 'drop', 'forwardWithMods', 'interceptoff']) {
    const { context, exports, messages } = agent();
    let waits = 0;
    let restored = 0;
    let ended = false;
    const interrupted = Object.assign(new Error('java.lang.InterruptedException'), { $h: {}, interrupted: true });
    context.Java.cast = error => error;
    context.Java.use = name => {
      if (name === 'java.lang.InterruptedException') return { class: { isInstance: e => e.interrupted === true } };
      if (name === 'java.lang.Throwable') return {};
      assert.equal(name, 'java.lang.Thread');
      return { currentThread: () => ({ interrupt() { assert.equal(ended, true); restored++; } }) };
    };
    context.getStackTrace = () => [];
    context.dumpIntent = () => ({});
    context.beginHold = () => 'hold-interrupt';
    context.endHold = () => { ended = true; };
    context.applyModifications = () => { assert.equal(restored, 0); return { ok: true }; };
    context.lock = {
      notify() {},
      wait() {
        assert.equal(restored, 0);
        if (++waits <= 2) throw interrupted;
        assert.equal(waits, 3);
        if (operation === 'forwardWithMods') {
          exports.forwardWithMods([{ type: 'action', key: '', val: 'edited', extraType: '' }], context.activeDecisionId);
        } else exports[operation](context.activeDecisionId);
      },
    };
    assert.equal(context.processIntercept('Example', 'onReceive', {}, null, null), operation === 'drop');
    assert.equal(restored, 1);
    assert.equal(waits, 3);
    assert.equal(messages.some(m => typeof m === 'string' && m.includes('Blocking Error')), false);
  }
});

test('the first accepted decision cannot be overwritten by another RPC or cleanup', () => {
  for (const first of ['forward', 'drop', 'forwardWithMods']) {
    const { context, exports } = agent();
    let notifications = 0;
    context.waiting = true;
    context.activeIntentPresent = true;
    context.activeDecisionId = 'decision-once';
    context.lock = { notify() { notifications++; } };
    const mods = [{ type: 'action', key: '', val: 'first-draft', extraType: '' }];
    assert.equal(first === 'forwardWithMods'
      ? exports.forwardWithMods(mods, 'decision-once') : exports[first]('decision-once'), true);
    assert.equal(exports.forward('decision-once'), false);
    assert.equal(exports.drop('decision-once'), false);
    assert.equal(exports.forwardWithMods([], 'decision-once'), false);
    assert.equal(exports.interceptOffWithMods([], 'decision-once'), false);
    assert.equal(exports.stageMod('action', '', 'late-change', '', 'decision-once'), false);
    exports.interceptoff();
    assert.equal(context.blockEnabled, false);
    assert.equal(context.resumeMode, first === 'drop' ? 'drop' : 'forward');
    assert.equal(context.modQueue.length, first === 'forwardWithMods' ? 1 : 0);
    if (first === 'forwardWithMods') assert.equal(context.modQueue[0].val, 'first-draft');
    assert.equal(notifications, 1);
  }
});

test('a failed notification can be retried and is not reported as accepted', () => {
  const { context, exports } = agent();
  context.waiting = true;
  context.activeDecisionId = 'decision-retry';
  context.lock = { notify() { throw new Error('monitor failure'); } };
  assert.equal(exports.forward('decision-retry'), false);
  assert.equal(context.resumeRequested, false);
  context.lock.notify = () => {};
  assert.equal(exports.drop('decision-retry'), true);
  assert.equal(context.resumeMode, 'drop');
});

test('new captures distinguish a null Intent from a present empty Intent without mutating metadata', () => {
  for (const intent of [null, {}]) {
    const { context, messages } = agent();
    context.getStackTrace = () => [];
    context.dumpIntent = () => ({});
    context.blockEnabled = false;
    const surface = { callerExported: true };
    context.processIntercept('Example', 'onStartCommand', intent, null, surface);
    const event = messages.find(item => item.noxenEvent === 'intent');
    assert.equal(event.attackSurface.intentPresent, intent !== null);
    assert.equal(event.attackSurface.callerExported, true);
    assert.equal('intentPresent' in surface, false);
    assert.equal(event.decision.required, false);
  }
});

test('a null held Intent rejects modifications but can still forward, drop or disable interception', () => {
  for (const operation of ['forward', 'drop', 'forwardWithMods', 'interceptOffWithMods']) {
    const { context, exports } = agent();
    let notifications = 0;
    context.waiting = true;
    context.activeDecisionId = 'decision-null';
    context.activeIntentPresent = false;
    context.lock = { notify() { notifications++; } };
    const mods = [{ type: 'extra_add', key: 'key', val: 'value', extraType: 'string' }];
    assert.equal(exports.stageMod('action', '', 'changed', '', 'decision-null'), false);
    assert.equal(exports.forwardWithMods(mods, 'decision-null'), false);
    assert.equal(exports.interceptOffWithMods(mods, 'decision-null'), false);
    assert.equal(context.modQueue.length, 0);
    assert.equal(context.blockEnabled, true);
    assert.equal(notifications, 0);
    assert.equal(operation.endsWith('WithMods')
      ? exports[operation]([], 'decision-null') : exports[operation]('decision-null'), true);
    assert.equal(notifications, 1);
  }
});

test('a busy null event does not overwrite the presence of an already held Intent', () => {
  const { context } = agent();
  context.waiting = true;
  context.activeIntentPresent = true;
  context.getStackTrace = () => [];
  context.dumpIntent = () => ({});
  context.processIntercept('Example', 'onStartCommand', null, null, null);
  assert.equal(context.activeIntentPresent, true);
});

test('declared Intent arguments preserve subclasses and null values', () => {
  for (const intent of [null, { $className: 'example.CustomIntent' }]) {
    const { context } = agent();
    let captured;
    context.buildAttackSurface = () => ({});
    context.processIntercept = (_class, _method, value) => { captured = value; return false; };
    const method = { returnType: { className: 'void' }, apply(_self, args) { assert.equal(args[1], intent); } };
    const target = { customMethod: { overload: () => method } };
    context.createHook(target, 'Example', 'customMethod', ['int', 'android.content.Intent']);
    method.implementation.call({ $className: 'Example' }, 7, intent);
    assert.equal(captured, intent);
  }
});
