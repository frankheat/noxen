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

function makeHook(methodName, returnType, original, shouldDrop = false) {
  const messages = [];
  const context = vm.createContext({
    Java: {},
    rpc: {},
    send: message => messages.push(message),
  });
  vm.runInContext(agentSource, context, { filename: agentPath });
  context.buildAttackSurface = () => null;
  context.processIntercept = () => shouldDrop;

  let callCount = 0;
  const overload = {
    returnType: { className: returnType },
    apply(receiver, args) {
      callCount++;
      return original(receiver, args);
    },
  };
  const target = { [methodName]: { overload: () => overload } };
  context.createHook(target, 'android.content.ContextWrapper', methodName, []);
  return {
    call: (...args) => overload.implementation.apply({ $className: 'Example' }, args),
    messages,
    calls: () => callCount,
  };
}

test('a Java exception from the original method reaches the caller unchanged', () => {
  const javaException = Object.assign(new Error('Activity not found'), { $h: 'java-throwable' });
  const hook = makeHook('startActivity', 'void', () => { throw javaException; });

  assert.throws(() => hook.call({ $className: 'android.content.Intent' }), error => error === javaException);
  assert.equal(hook.calls(), 1);
});

test('the caller can catch the original exception and execute its fallback', () => {
  const javaException = Object.assign(new Error('Activity not found'), { $h: 'java-throwable' });
  const hook = makeHook('startActivity', 'void', () => { throw javaException; });
  let fallbackRan = false;

  try {
    hook.call({ $className: 'android.content.Intent' });
  } catch (error) {
    assert.equal(error, javaException);
    fallbackRan = true;
  }

  assert.equal(fallbackRan, true);
});

test('a successful original call preserves its return value and arguments', () => {
  const component = { name: 'ExampleService' };
  const intent = { $className: 'android.content.Intent' };
  const hook = makeHook('startService', 'android.content.ComponentName', (receiver, args) => {
    assert.equal(receiver.$className, 'Example');
    assert.equal(args[0], intent);
    return component;
  });

  assert.equal(hook.call(intent), component);
  assert.equal(hook.calls(), 1);
});

test('Drop still skips the original method and returns its default', () => {
  const hook = makeHook('startService', 'android.content.ComponentName', () => {
    throw new Error('original method must not be called');
  }, true);

  assert.equal(hook.call({ $className: 'android.content.Intent' }), null);
  assert.equal(hook.calls(), 0);
});

test('getIntent continues to propagate an exception from the original method', () => {
  const javaException = Object.assign(new Error('getIntent failed'), { $h: 'java-throwable' });
  const hook = makeHook('getIntent', 'android.content.Intent', () => { throw javaException; });

  assert.throws(() => hook.call(), error => error === javaException);
  assert.equal(hook.calls(), 1);
});
