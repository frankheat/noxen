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
  return { context, messages, exports: context.rpc.exports };
}

test('intent events identify protocol and retain explicit blocking/passive decisions', () => {
  for (const state of ['blocking', 'passive', 'busy']) {
    const { context, messages } = agent();
    context.getStackTrace = () => [];
    context.dumpIntent = () => ({});
    context.beginHold = () => 'h1';
    context.endHold = () => {};
    context.lock = { wait() {} };
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
    context.activeDecisionId = 'decision-current';
    context.lock = { notify() { notifications++; } };
    const mods = [{ type: 'action', key: '', val: 'changed', extraType: '' }];
    const call = id => operation.endsWith('WithMods')
      ? exports[operation](mods, id) : exports[operation](id);
    assert.equal(call('decision-current'), true);
    assert.equal(notifications, 1);
    assert.equal(context.resumeMode, operation === 'drop' ? 'drop' : 'forward');
    context.activeDecisionId = 'decision-next';
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
