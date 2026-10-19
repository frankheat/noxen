const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const agentPath = path.join(__dirname, '..', 'agent', 'script.js');
const agentSource = fs.readFileSync(agentPath, 'utf8').replace(
  /^import Java_bridge from 'frida-java-bridge';/,
  'const Java_bridge = {};'
);

function runIntercept(mods, floatParser = value => Number(value)) {
  const messages = [];
  const floatValues = [];
  const java = {
    synchronized(_lock, callback) { callback(); },
    use(className) {
      if (className === 'android.content.ComponentName') {
        return { unflattenFromString(value) {
          const [pkg, name] = value.split('/');
          return pkg + '/' + (name.startsWith('.') ? pkg + name : name);
        } };
      }
      if (className === 'java.lang.Float') {
        return { valueOf(value) {
          floatValues.push(value);
          return { floatValue() { return floatParser(value); } };
        } };
      }
      throw new Error(`Unexpected Java class: ${className}`);
    },
  };
  const context = vm.createContext({ Java: java, Process: { id: 123 }, rpc: {}, send: value => messages.push(value) });
  vm.runInContext(agentSource, context, { filename: agentPath });
  context.getStackTrace = () => [];
  context.beginHold = () => 'hold-1';
  context.endHold = () => {};
  context.dumpIntent = intent => ({
    component: intent.component,
    action: intent.action, data: intent.data, mimeType: intent.mimeType,
    flags: intent.flags, categories: [...intent.categories], extras: { ...intent.extras },
  });
  context.UriJava = { parse: value => value };
  context.lock = { wait() { context.modQueue = mods; context.resumeMode = 'forward'; } };

  const intent = {
    component: 'example/example.Old',
    selector: { component: 'example/example.Selector' }, clipData: { text: 'keep' },
    action: 'original', data: 'content://old', mimeType: 'text/plain',
    flags: 0x10, categories: new Set(['old.category']), extras: { stale: 'old' },
    setAction(value) { this.action = value; },
    setComponent(value) { this.component = value; },
    getData() { return this.data; },
    getType() { return this.mimeType; },
    setDataAndType(data, mimeType) { this.data = data; this.mimeType = mimeType; },
    getFlags() { return this.flags; },
    setFlags(value) { this.flags = value; },
    addCategory(value) { this.categories.add(value); },
    removeCategory(value) { this.categories.delete(value); },
    removeExtra(key) { delete this.extras[key]; },
    putExtra: { overload() { return { call(receiver, key, value) { receiver.extras[key] = value; } }; } },
  };
  const dropped = context.processIntercept('Example', 'startActivity', intent, null, null);
  return { dropped, intent, messages, floatValues };
}

test('successful modifications are reported with the observed Intent and decision ID', () => {
  const result = runIntercept([
    { type: 'action', val: 'changed' },
    { type: 'extra_add', key: 'note', val: 'hello', extraType: 'string' },
  ]);
  const report = result.messages.find(message => message.noxenEvent === 'modification_result');
  assert.equal(result.dropped, false);
  assert.equal(report.ok, true);
  assert.equal(report.decisionId, 'decision-123-1');
  assert.equal(report.infoIntent.action, 'changed');
  assert.equal(report.infoIntent.extras.note, 'hello');
});

test('a failure reports the partially changed Intent and skips later modifications', () => {
  const result = runIntercept([
    { type: 'action', val: 'changed' },
    { type: 'extra_add', key: 'bad', val: 'bad', extraType: 'float' },
    { type: 'extra_add', key: 'later', val: 'hello', extraType: 'string' },
  ], () => { throw new Error('NumberFormatException'); });
  const report = result.messages.find(message => message.noxenEvent === 'modification_result');
  assert.equal(report.ok, false);
  assert.match(report.error, /NumberFormatException/);
  assert.equal(report.infoIntent.action, 'changed');
  assert.deepEqual(report.infoIntent.extras, { stale: 'old' });
});

test('lowercase special floating values are normalized before Java parsing', () => {
  const result = runIntercept([
    { type: 'extra_add', key: 'score', val: 'nan', extraType: 'float' },
  ], value => {
    assert.equal(value, 'NaN');
    return NaN;
  });
  const report = result.messages.find(message => message.noxenEvent === 'modification_result');
  assert.equal(report.ok, true);
  assert.deepEqual(result.floatValues, ['NaN']);
});

test('an unmodified forward does not send a modification result', () => {
  const result = runIntercept([]);
  assert.equal(result.messages.some(message => message.noxenEvent === 'modification_result'), false);
});

test('component replacement expands a relative class and leaves nested objects untouched', () => {
  const result = runIntercept([{ type: 'component', val: 'other/.Target' }]);
  const report = result.messages.find(message => message.noxenEvent === 'modification_result');
  assert.equal(report.ok, true);
  assert.equal(report.infoIntent.component, 'other/other.Target');
  assert.equal(result.intent.selector.component, 'example/example.Selector');
  assert.equal(result.intent.clipData.text, 'keep');
  assert.equal(result.intent.action, 'original');
});

test('component removal sets null without deleting selector or package restrictions', () => {
  const result = runIntercept([{ type: 'component', val: '' }]);
  const report = result.messages.find(message => message.noxenEvent === 'modification_result');
  assert.equal(report.ok, true);
  assert.equal(report.infoIntent.component, null);
  assert.equal(result.intent.selector.component, 'example/example.Selector');
});

test('malformed component values fail without applying a later modification', () => {
  for (const value of ['missingSlash', '/Class', 'pkg/', 'pkg/A/B', 'pkg/.', 'pkg/A B', 'pkg/A\u0000B']) {
    const result = runIntercept([{ type: 'component', val: value }, { type: 'action', val: 'later' }]);
    const report = result.messages.find(message => message.noxenEvent === 'modification_result');
    assert.equal(report.ok, false, value);
    assert.equal(report.infoIntent.component, 'example/example.Old');
    assert.equal(report.infoIntent.action, 'original');
  }
});

test('confirmation cannot confuse an unreadable Component with an observed null', () => {
  const context = vm.createContext({ Java: {}, rpc: {}, send() {} });
  vm.runInContext(agentSource, context, { filename: agentPath });
  const unreadable = { getComponent() { throw new Error('component read failed'); } };
  assert.throws(() => context.dumpIntent(unreadable, true), /component read failed/);
  assert.equal(context.dumpIntent(unreadable).component, null); // Passive capture fallback unchanged.
  assert.equal(context.dumpIntent({ getComponent() { return null; } }, true).component, null);
});

test('data and MIME changes preserve each other and the result includes flags and categories', () => {
  const result = runIntercept([
    { type: 'data', val: 'content://new' },
    { type: 'mime', val: 'image/png' },
    { type: 'flag_add', val: '0x20' },
    { type: 'flag_rem', val: '0x10' },
    { type: 'cat_rem', val: 'old.category' },
    { type: 'cat_add', val: 'new.category' },
    { type: 'extra_rem', key: 'stale' },
  ]);
  const report = result.messages.find(message => message.noxenEvent === 'modification_result');
  assert.equal(report.ok, true);
  assert.equal(report.infoIntent.data, 'content://new');
  assert.equal(report.infoIntent.mimeType, 'image/png');
  assert.equal(report.infoIntent.flags, 0x20);
  assert.deepEqual(report.infoIntent.categories, ['new.category']);
  assert.deepEqual(report.infoIntent.extras, {});
});
