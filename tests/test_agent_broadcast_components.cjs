const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'agent', 'script.js'), 'utf8')
  .replace(/^import Java_bridge from 'frida-java-bridge';/, 'const Java_bridge = {};');
function intent(name = null, selector = null) {
  return { getComponent: () => name ? {
    getPackageName: () => 'example', getClassName: () => name,
  } : null, getSelector: () => selector };
}
function agent(unavailable = false) {
  const queries = [];
  const pm = {
    getReceiverInfo(cn) {
      const name = cn.getClassName();
      queries.push(name);
      if (name === 'Missing') throw new Error('not found');
      return { exported: { value: name !== 'Selector' }, permission: { value: 'example.SEND' } };
    },
    getPermissionInfo() {
      return { protectionLevel: { value: 2 }, packageName: { value: 'example' } };
    },
    queryBroadcastReceivers() { queries.push('implicit lookup'); throw new Error('Unexpected implicit lookup'); },
  };
  const app = { getPackageManager: () => unavailable ? null : pm };
  const context = vm.createContext({ Java: { use: () => ({ currentApplication: () => app }) },
    rpc: {}, send() {} });
  vm.runInContext(source, context);
  return { queries, capture: (method, payload, permission = null) => JSON.parse(JSON.stringify(
    context.buildAttackSurface(method, payload, app, app, permission)
  )) };
}

test('broadcast send, ordered, factory and receive capture named components without routing', () => {
  for (const method of ['sendBroadcast', 'sendOrderedBroadcast', 'getBroadcast', 'onReceive']) {
    const { capture } = agent();
    const surface = capture(method, intent('Base', intent('Selector')), 'example.RECEIVE');
    assert.equal(surface.broadcastComponents.base.component, 'example/Base');
    assert.equal(surface.broadcastComponents.selector.exported, false);
    assert.equal(surface.broadcastComponents.base.permission.name, 'example.SEND');
    assert.deepEqual(Object.keys(surface).sort(),
      ['sendBroadcast', 'sendOrderedBroadcast'].includes(method)
        ? ['broadcastComponents', 'broadcastPermission'] : ['broadcastComponents']);
    if (surface.broadcastPermission) assert.equal(surface.broadcastPermission.name, 'example.RECEIVE');
  }
});

test('implicit and nested-selector broadcasts perform no component queries', () => {
  for (const payload of [intent(), intent(null, intent()), intent(null, intent(null, intent('Deep')))]) {
    const { capture, queries } = agent();
    assert.deepEqual(capture('sendBroadcast', payload), { broadcastComponents: {}, broadcastPermission: null });
    assert.deepEqual(queries, []);
  }
});

test('equal names share one query and a missing component does not hide the other', () => {
  const first = agent();
  first.capture('getBroadcast', intent('Base', intent('Base')));
  assert.deepEqual(first.queries, ['Base']);
  const surface = agent().capture('sendBroadcast', intent('Missing', intent('Selector')));
  assert.equal(surface.broadcastComponents.base.unavailable, true);
  assert.equal(surface.broadcastComponents.selector.exported, false);
});

test('permission argument survives absent PackageManager and null Intent', () => {
  const { capture } = agent(true);
  const surface = capture('sendOrderedBroadcast', intent('Base'), 'example.RECEIVE');
  assert.deepEqual(surface.broadcastPermission,
    { name: 'example.RECEIVE', level: 'unresolved', definedBy: null });
  assert.equal(surface.broadcastComponents.base.unavailable, true);
  assert.deepEqual(capture('sendBroadcast', null), { broadcastPermission: null });
  assert.deepEqual(capture('sendBroadcast', intent(), '').broadcastPermission,
    { name: '', level: 'unresolved', definedBy: null });
});

test('selector getter failure preserves base component and independent call permission', () => {
  const payload = intent('Base');
  payload.getSelector = () => { throw new Error('unreadable'); };
  const surface = agent().capture('sendBroadcast', payload, 'example.RECEIVE');
  assert.equal(surface.broadcastComponents.base.exported, true);
  assert.equal(surface.broadcastPermission.level, 'signature');
});

test('hook extracts receiverPermission rather than AppOp and preserves null and empty arguments', () => {
  for (const permission of [null, '', 'example.RECEIVE']) {
    const context = vm.createContext({ Java: {}, rpc: {}, send() {} });
    vm.runInContext(source, context);
    let captured;
    let calls = 0;
    context.buildAttackSurface = (_method, _intent, _self, _first, value) => { captured = value; };
    context.processIntercept = () => false;
    const overload = { returnType: { className: 'void' }, apply() { calls++; } };
    const target = { sendOrderedBroadcast: { overload: () => overload } };
    context.createHook(target, 'android.content.ContextWrapper', 'sendOrderedBroadcast',
      ['android.content.Intent', 'int', 'java.lang.String', 'java.lang.String']);
    overload.implementation.call({ $className: 'Example' },
      { $className: 'android.content.Intent' }, 0, permission, 'different.AppOp');
    assert.equal(captured, permission);
    assert.equal(calls, 1);
  }
});
