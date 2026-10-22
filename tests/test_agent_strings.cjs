const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'agent', 'script.js'), 'utf8')
  .replace(/^import Java_bridge from 'frida-java-bridge';/, 'const Java_bridge = {};');

function agent() {
  const reads = [], releases = [];
  const env = {
    isInstanceOf(handle) { return !handle.nonString; },
    getStringLength(handle) { return handle.text.length; },
    getStringChars(handle) {
      return {
        isNull() { return false; },
        readByteArray(bytes) {
          reads.push(bytes);
          if (handle.fail) throw new Error('Read failed');
          return Uint16Array.from(handle.text.slice(0, bytes / 2).split(''), c => c.charCodeAt(0)).buffer;
        },
      };
    },
    releaseStringChars(handle) { releases.push(handle); },
  };
  const java = {
    vm: { getEnv() { return env; } },
    array(type, items) { return items; },
    use(name) {
      if (name === 'java.lang.String') return {
        class: { $h: 'String.class' },
        $new(chars) { return { $h: { text: chars.join('') } }; },
      };
      throw new Error(`Unexpected class ${name}`);
    },
  };
  const context = vm.createContext({ Java: java, rpc: {}, send() {} });
  vm.runInContext(source, context);
  return { context, reads, releases, env };
}

test('well-formedness agrees with UTF-16 pairing, including adjacent pairs and controls', () => {
  const { context } = agent();
  const chars = ['a', '\0', '\n', '\ud800', '\udbff', '\udc00', '\udfff'];
  for (const fallback of [false, true]) {
    if (fallback) vm.runInContext('String.prototype.isWellFormed = undefined;', context);
    for (const a of chars) for (const b of chars) for (const c of chars) {
      const text = a + b + c;
      if (text.isWellFormed()) assert.equal(context.requireWellFormedText(text), text);
      else assert.throws(() => context.requireWellFormedText(text), error =>
        error.name === 'InvalidUTF16' && !/[\ud800-\udfff]/.test(error.message));
    }
  }
});

test('bounded Java strings retain NUL, controls and Unicode without stringifying', () => {
  const { context, releases } = agent();
  for (const text of ['', '\0', '\0a', 'a\0b\x1bc', 'a\0', 'caffè 日本語 🙂 👩‍💻']) {
    const value = { $h: { text }, toString() { throw new Error('Lossy conversion'); } };
    const result = context.boundedExtraText(value, true);
    assert.equal(result.value, text);
    assert.equal(result.originalLength, text.length);
    assert.equal(result.truncated, false);
  }
  assert.equal(releases.length, 6);
});

test('extraction is bounded, measures actual length and never splits a surrogate pair', () => {
  const { context, reads } = agent();
  for (const text of ['a'.repeat(2048), 'a'.repeat(2048) + '\0tail', 'a'.repeat(2047) + '🙂', '🙂'.repeat(2000)]) {
    const result = context.boundedExtraText({ $h: { text } }, true);
    assert.equal(result.originalLength, text.length);
    assert.ok(result.value.isWellFormed());
    assert.ok(result.value.length <= 2048);
    assert.equal(result.truncated, result.value.length < text.length);
    assert.ok(text.startsWith(result.value));
  }
  assert.ok(reads.every(bytes => bytes <= 4098));
});

test('JNI characters are always released, including read and validation failures', () => {
  const { context, releases } = agent();
  const failed = { text: 'safe', fail: true };
  assert.throws(() => context.boundedExtraText({ $h: failed }, true), /Read failed/);
  const malformed = { text: 'a\ud800b' };
  assert.throws(() => context.boundedExtraText({ $h: malformed }, true), /unpaired/);
  assert.deepEqual(releases, [failed, malformed]);
});

test('a non-String Bundle key never reaches JNI string reads', () => {
  const { context, reads, releases } = agent();
  assert.throws(() => context.boundedExtraText({ $h: { nonString: true } }, true), /Expected a Java String/);
  assert.deepEqual(reads, []);
  assert.deepEqual(releases, []);
});

test('bad strings produce an error node and cannot become editable collections', () => {
  const { context } = agent();
  context.extraTypeName = () => 'java.lang.String';
  const node = context.serializeExtraNode({ $h: { text: '\ud800' } }, { nodes: 0 }, 0);
  assert.equal(node.kind, 'error');
  assert.match(node.reason, /InvalidUTF16/);
  assert.equal(context.extraEnvelopeFromNode(node).editable, false);
  assert.equal(context.legacyCollectionValue({ kind: 'array', type: '[Ljava.lang.String;', count: 1, items: [node] }), null);
});

test('Character values are cast from Object before reading their char, including NUL', () => {
  const { context } = agent();
  context.Java.use = name => { assert.equal(name, 'java.lang.Character'); return 'Character.class'; };
  context.Java.cast = (object, klass) => {
    assert.equal(klass, 'Character.class');
    return { charValue() { return object.char; } };
  };
  for (const char of ['A', '\0', '界']) {
    const node = context.scalarExtraNode({ char }, 'java.lang.Character');
    assert.equal(node.value, char);
    assert.equal(node.displayType, 'char');
  }
  assert.throws(() => context.scalarExtraNode({ char: '\ud800' }, 'java.lang.Character'), /unpaired/);
});

test('normal writes stay on the ordinary path; NUL uses exact Java char construction', () => {
  const { context } = agent();
  for (const text of ['', 'hello', '🙂', '日本語', 'literal\\0']) {
    assert.equal(context.javaStringArgument(text), text);
  }
  assert.equal(context.javaStringArgument('a\0b').$h.text, 'a\0b');
  assert.throws(() => context.javaStringArgument('\ud800'), /unpaired/);
  assert.equal(context.javaStringArgument(null), null);
});

test('malformed RPC modifications are rejected before any queue is published', () => {
  const { context } = agent();
  for (const field of ['key', 'val', 'extraType']) {
    const mod = { type: 'extra_add', key: 'key', val: 'value', extraType: 'string', [field]: '\ud800' };
    assert.throws(() => context.normalizeRpcMods([mod]), /unpaired/);
  }
  assert.equal(context.normalizeRpcMods([{ type: 'action', val: 'a\0b' }])[0].val, 'a\0b');
});
