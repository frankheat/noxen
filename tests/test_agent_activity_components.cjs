const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'agent', 'script.js'), 'utf8')
  .replace(/^import Java_bridge from 'frida-java-bridge';/, 'const Java_bridge = {};');

function component(name) {
  return { getPackageName: () => 'example', getClassName: () => name };
}

function intent(name = null, selector = null) {
  return { getComponent: () => name ? component(name) : null,
    getSelector: () => selector, getPackage: () => null };
}

function agent() {
  const queries = [];
  const value = item => ({ value: item });
  const pm = {
    getActivityInfo(cn) {
      const name = cn.getClassName();
      queries.push(['activity', name]);
      if (name === 'Missing') throw new Error('Unavailable');
      return { exported: value(name === 'Base'), permission: value(name === 'Selector' ? 'example.SIGNATURE' : null),
        applicationInfo: value({ permission: value(null) }) };
    },
    getPermissionInfo: () => ({ protectionLevel: value(2), packageName: value('example') }),
    resolveActivity() { queries.push(['resolveActivity']); throw new Error('Must not resolve Activities'); },
    resolveService() { queries.push(['resolveService']); return null; },
    queryBroadcastReceivers() { queries.push(['queryBroadcastReceivers']); return null; },
  };
  const app = { getPackageManager: () => pm, getPackageName: () => 'example', $className: 'Base' };
  const context = vm.createContext({
    Java: { use(name) {
      if (name === 'android.app.ActivityThread') return { currentApplication: () => app };
      if (name === 'android.content.ComponentName') return { $new: (_pkg, name) => component(name) };
      throw new Error('Unexpected class ' + name);
    } }, rpc: {}, send() {},
  });
  vm.runInContext(source, context);
  const capture = (method, payload, self = app) => JSON.parse(JSON.stringify(
    context.buildAttackSurface(method, payload, self, app, null)
  ));
  return { capture, queries, context, app };
}

test('Activity sends, PendingIntent factory and callbacks keep independent named components without routing', () => {
  for (const method of ['startActivity', 'startActivityForResult', 'getActivity', 'getIntent', 'onNewIntent', 'onActivityResult', 'setResult']) {
    const { capture, queries } = agent();
    const surface = capture(method, intent('Base', intent('Selector')));
    assert.deepEqual(surface.activityComponents, {
      base: { component: 'example/Base', exported: true, permission: null },
      selector: { component: 'example/Selector', exported: false,
        permission: { name: 'example.SIGNATURE', level: 'signature', definedBy: 'example' } },
    });
    for (const key of ['intentExplicit', 'routingSource', 'selectorRoutingRole', 'routingPackage', 'targetComponent', 'targetType']) {
      assert.equal(key in surface, false, method + ': ' + key);
    }
    assert.equal(queries.some(query => query[0] === 'resolveActivity'), false);
  }
});

test('implicit Activity fields are not resolved, including when only a nested selector names a component', () => {
  for (const payload of [intent(), intent(null, intent()), intent(null, intent(null, intent('Selector')))]) {
    const { capture, queries } = agent();
    assert.deepEqual(capture('startActivity', payload), { activityComponents: {} });
    assert.deepEqual(queries, []);
  }
});

test('equal base and selector components reuse a single metadata lookup', () => {
  const { capture, queries } = agent();
  const surface = capture('getActivity', intent('Base', intent('Base')), {});
  assert.equal(surface.activityComponents.base.exported, true);
  assert.deepEqual(surface.activityComponents.base, surface.activityComponents.selector);
  assert.deepEqual(queries, [['activity', 'Base']]);
});

test('one unavailable component does not hide the other or claim package invisibility', () => {
  const { capture } = agent();
  const surface = capture('startActivity', intent('Missing', intent('Selector')));
  assert.deepEqual(surface.activityComponents.base, { component: 'example/Missing', unavailable: true });
  assert.equal(surface.activityComponents.selector.exported, false);
  assert.equal(surface.targetUnreadable, undefined);
});

test('selector read failure and null Intent do not break the hook', () => {
  const { capture } = agent();
  const payload = intent('Base');
  payload.getSelector = () => { throw new Error('Cannot read selector'); };
  assert.equal(capture('startActivity', payload).activityComponents.base.exported, true);
  assert.deepEqual(capture('startActivity', null), {});
});

test('unavailable PackageManager preserves both named components', () => {
  const { capture, app } = agent();
  app.getPackageManager = () => null;
  const surface = capture('startActivity', intent('Base', intent('Selector')));
  assert.equal(surface.activityComponents.base.unavailable, true);
  assert.equal(surface.activityComponents.selector.unavailable, true);
});

test('unknown custom methods do not acquire a routing interpretation', () => {
  const { capture, queries } = agent();
  assert.deepEqual(capture('customMethod', intent('Base', intent('Selector'))), {});
  assert.deepEqual(queries, []);
});
