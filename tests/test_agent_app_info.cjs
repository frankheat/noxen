const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'agent', 'script.js'), 'utf8')
  .replace(/^import Java_bridge from 'frida-java-bridge';/, 'const Java_bridge = {};');

function snapshotAgent(sdk) {
  const runtime = new Map();
  const queries = [];
  const fields = ['activities', 'services', 'receivers', 'providers'];
  const value = item => ({ value: item });
  const pm = {
    getComponentEnabledSetting: name => runtime.get(name) || 0,
    getPackageInfo(_pkg, flags) {
      queries.push(flags);
      const info = { applicationInfo: value({ flags: value(0) }) };
      for (const field of fields) {
        info[field] = value([true, false].map(enabled => {
          const name = field + (enabled ? '.Enabled' : '.Disabled');
          const state = runtime.get(name) || 0;
          return {
            name: value(name), enabled: value(state ? state === 1 : enabled),
            exported: value(true), permission: value(null), targetActivity: value(null),
            readPermission: value(null), writePermission: value(null),
            pathPermissions: value(null), uriPermissionPatterns: value(null),
          };
        }).filter(ci => ci.enabled.value || (flags & 512)));
      }
      return info;
    },
  };
  const classes = {
    'android.app.ActivityThread': {
      currentApplication: () => ({ getPackageManager: () => pm, getPackageName: () => 'example' }),
    },
    'android.os.Build$VERSION': { SDK_INT: value(sdk) },
    'android.content.ComponentName': { $new: (_pkg, name) => name },
  };
  const context = vm.createContext({
    Java: { performNow: fn => fn(), use: name => {
      if (!(name in classes)) throw new Error('Not mocked: ' + name);
      return classes[name];
    } },
    Process: { id: 42 }, rpc: {}, send() {},
  });
  vm.runInContext(source, context);
  return { snapshot: () => context.rpc.exports.getAppInfo(), runtime, queries };
}

test('Info app includes enabled and manifest-disabled components of every type', () => {
  for (const sdk of [27, 31]) {
    const { snapshot, queries } = snapshotAgent(sdk);
    const info = snapshot();
    assert.equal(info.error, undefined);
    assert.equal(info.components.length, 8);
    for (const type of ['activity', 'service', 'receiver', 'provider']) {
      const items = info.components.filter(ci => ci.type === type);
      assert.equal(items.length, 2);
      assert.equal(items.filter(ci => ci.enabled).length, 1);
    }
    assert.equal(queries.length, 1);
    assert.ok(queries[0] & 512);
    assert.equal(Boolean(queries[0] & 134217728), sdk >= 28);
    assert.equal(Boolean(queries[0] & 64), sdk < 28);
  }
});

test('refresh retains runtime-disabled components and observes re-enabling and defaults', () => {
  const { snapshot, runtime } = snapshotAgent(31);
  for (const state of [2, 1, 0]) {
    runtime.set('receivers.Enabled', state);
    runtime.set('activities.Disabled', state);
    const info = snapshot();
    assert.equal(info.error, undefined);
    assert.equal(info.components.length, 8);
    for (const name of ['receivers.Enabled', 'activities.Disabled']) {
      const ci = info.components.find(item => item.name === name);
      assert.equal(ci.enabledRuntime, state);
      assert.equal(ci.enabled, state ? state === 1 : name.endsWith('.Enabled'));
    }
  }
});
