const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function agent() {
  let now = 1000;
  const source = fs.readFileSync(path.join(__dirname, '..', 'agent', 'system_server.js'), 'utf8')
    .replace(/^import Java_bridge from 'frida-java-bridge';/, 'const Java_bridge = {};');
  const context = vm.createContext({ rpc: {}, send() {}, Date: { now: () => now } });
  vm.runInContext(source, context);
  return { exports: context.rpc.exports, context, advance: ms => { now += ms; } };
}

test('a delayed end cannot remove a different hold on the same PID', () => {
  const { exports, context } = agent();
  exports.holdstart({ holdId: 'h2', pid: 42 });
  exports.holdend('h1', 42);
  assert.equal(context.activeHolds['42'].holdId, 'h2');
  exports.holdend('h2', '42');
  assert.equal(exports.status().activeHolds, 0);
});

test('a provided PID must match; missing PID can still end a hold by ID', () => {
  const { exports, context } = agent();
  exports.holdstart({ holdId: 'h1', pid: 42 });
  exports.holdstart({ holdId: 'h2', pid: 43 });
  exports.holdend('h1', 43);
  exports.holdend('h1', 44);
  assert.equal(exports.status().activeHolds, 2);
  exports.holdend('h1', null);
  assert.equal(exports.status().activeHolds, 1);
  assert.equal(context.activeHolds['43'].holdId, 'h2');
  exports.holdend('h2');
  assert.equal(exports.status().activeHolds, 0);
});

test('duplicate ends are harmless even after the next hold starts', () => {
  const { exports, context } = agent();
  exports.holdstart({ holdId: 'h1', pid: 42 });
  exports.holdend('h1', 42);
  exports.holdend('h1', 42);
  exports.holdstart({ holdId: 'h2', pid: 42 });
  exports.holdend('h1', 42);
  assert.equal(context.activeHolds['42'].holdId, 'h2');
});

test('hold expiry and clear retain their existing behavior', () => {
  const { exports, advance } = agent();
  exports.holdstart({ holdId: 'h1', pid: 42 });
  exports.holdstart({ holdId: 'h2', pid: 43, timeoutMs: 2000 });
  advance(2001);
  assert.equal(exports.status().activeHolds, 1);
  advance(120000);
  assert.equal(exports.status().activeHolds, 0);
  exports.holdstart({ holdId: 'h3', pid: 42 });
  exports.clear();
  assert.equal(exports.status().activeHolds, 0);
});
