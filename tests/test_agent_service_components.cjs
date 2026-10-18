const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'agent', 'script.js'), 'utf8')
  .replace(/^import Java_bridge from 'frida-java-bridge';/, 'const Java_bridge = {};');
const methods = ['startService', 'startForegroundService', 'bindService', 'getService', 'onStartCommand', 'onBind'];
const component = name => ({ getPackageName: () => 'example', getClassName: () => name });
const intent = (name = null, selector = null) => ({
  getComponent: () => name === null ? null : component(name), getSelector: () => selector,
});

function agent(unavailable = false) {
  const queries = [];
  const pm = {
    getServiceInfo(cn) {
      const name = cn.getClassName();
      queries.push(name);
      if (name === 'Missing') throw new Error('not found');
      return { exported: { value: name === 'Selector' },
        permission: { value: name === 'Base' ? 'example.PROTECT' : null } };
    },
    getPermissionInfo: () => ({ protectionLevel: { value: 2 }, packageName: { value: 'example' } }),
    resolveService() { queries.push('implicit lookup'); throw new Error('Must not resolve'); },
  };
  const app = { getPackageManager: () => unavailable ? null : pm,
    getPackageName: () => 'example', $className: 'Caller' };
  const context = vm.createContext({ Java: { use(name) {
    if (name === 'android.content.ComponentName') return { $new: (_pkg, name) => component(name) };
    if (name === 'android.app.ActivityThread') return { currentApplication: () => app };
    throw new Error('Unexpected class ' + name);
  } }, rpc: {}, send() {} });
  vm.runInContext(source, context);
  return { queries, context, capture: (method, payload, self = app) => JSON.parse(JSON.stringify(
    context.buildAttackSurface(method, payload, self, app, null)
  )) };
}

test('all service methods preserve independent base and selector declarations without routing', () => {
  for (const method of methods) {
    const { capture, queries } = agent();
    const surface = capture(method, intent('Base', intent('Selector')));
    assert.deepEqual(surface.serviceComponents, {
      base: { component: 'example/Base', exported: false,
        permission: { name: 'example.PROTECT', level: 'signature', definedBy: 'example' } },
      selector: { component: 'example/Selector', exported: true, permission: null },
    });
    assert.equal(queries.includes('implicit lookup'), false);
    for (const field of ['intentExplicit', 'routingSource', 'selectorRoutingRole', 'targetComponent', 'targetType']) {
      assert.equal(field in surface, false, method + ': ' + field);
    }
    assert.equal('callerExported' in surface, ['onStartCommand', 'onBind'].includes(method));
  }
});

test('implicit and deeper-selector intents trigger no implicit lookup', () => {
  for (const method of methods.slice(0, 4)) {
    for (const payload of [intent(), intent(null, intent()), intent(null, intent(null, intent('Deep')))]) {
      const { capture, queries } = agent();
      assert.deepEqual(capture(method, payload), { serviceComponents: {} });
      assert.deepEqual(queries, []);
    }
  }
});

test('same component reuses a query, including static PendingIntent factory context', () => {
  const { capture, queries } = agent();
  const surface = capture('getService', intent('Base', intent('Base')), {});
  assert.deepEqual(surface.serviceComponents.base, surface.serviceComponents.selector);
  assert.deepEqual(queries, ['Base']);
});

test('unavailable component or PackageManager does not hide the captured names', () => {
  const first = agent().capture('startService', intent('Missing', intent('Selector')));
  assert.equal(first.serviceComponents.base.unavailable, true);
  assert.equal(first.serviceComponents.selector.exported, true);
  const second = agent(true).capture('bindService', intent('Base', intent('Selector')));
  assert.equal(second.serviceComponents.base.component, 'example/Base');
  assert.equal(second.serviceComponents.base.unavailable, true);
  assert.equal(second.serviceComponents.selector.unavailable, true);
});

test('null sticky callback preserves Class metadata without reading nonexistent Intent fields', () => {
  const { capture, queries } = agent();
  assert.deepEqual(capture('onStartCommand', null), { callerExported: false, callerPermission: null });
  assert.deepEqual(queries, ['Caller']);
  assert.deepEqual(capture('startService', null), {});
});

test('failure to read the selector leaves the base component intact', () => {
  const payload = intent('Base');
  payload.getSelector = () => { throw new Error('unreadable'); };
  assert.equal(agent().capture('startForegroundService', payload).serviceComponents.base.exported, false);
});
