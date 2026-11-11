// Passive, bounded Monitor. Unknown objects are never stringified or traversed.
const MAX_QUEUED_EVENTS = 512;
const RESOLVER = 'android.content.ContentResolver';
const SQLITE = 'android.database.sqlite.SQLiteDatabase';
const ANDROID_LOG = 'android.util.Log';
const CIPHER = 'javax.crypto.Cipher';
const URL_CLASS = 'java.net.URL';
const SOCKET_ADDRESS = 'java.net.SocketAddress';
const INET_SOCKET_ADDRESS = 'java.net.InetSocketAddress';
const URI = 'android.net.Uri';
const STRING = 'java.lang.String';
const FILE = 'java.io.File';
const FILES = 'java.nio.file.Files';
const PATH = 'java.nio.file.Path';
const COPY_OPTIONS = '[Ljava.nio.file.CopyOption;';
const COPY_OPTION_TYPES = new Set(['java.nio.file.StandardCopyOption', 'java.nio.file.LinkOption']);
const FRAMEWORK_URIS = new Set(['android.net.Uri$StringUri', 'android.net.Uri$HierarchicalUri', 'android.net.Uri$OpaqueUri']);
const FILE_CONSTRUCTORS = new Set(['java.io.FileInputStream', 'java.io.FileOutputStream', 'java.io.RandomAccessFile']);
const SQL_BOXED_SCALARS = new Set([
  STRING, 'java.lang.Long', 'java.lang.Double', 'java.lang.Integer', 'java.lang.Short',
  'java.lang.Byte', 'java.lang.Float', 'java.lang.Boolean',
]);

function sameObject(a, b) {
  if (a === b) return true;
  // Frida exposes Java object arrays as JS arrays with a backing Java wrapper.
  const left = Array.isArray(a) ? a.$w : a;
  const right = Array.isArray(b) ? b.$w : b;
  return left != null && right != null && left.$isSameObject(right);
}

// Match only known overload forwarding on the same Java object. Nested calls
// keep their own frame, even when their built-in event is folded.
function forwardsTo(parent, spec, receiver, args) {
  if (!parent || parent.spec.profile !== spec.profile || parent.spec.class !== spec.class
      || !sameObject(parent.receiver, receiver)) return false;
  const outer = parent.args;
  if (parent.spec.method !== spec.method) {
    // ContentResolver read opens can delegate through openAssetFileDescriptor.
    const caller = parent.spec.method;
    return spec.class === RESOLVER && spec.method === 'openTypedAssetFileDescriptor'
      && (caller === 'openInputStream' || (caller === 'openFileDescriptor' && outer[1] === 'r'))
      && sameObject(outer[0], args[0]) && args[1] === '*/*' && args[2] == null
      && (outer[2] == null ? args[3] == null : sameObject(outer[2], args[3]));
  }
  if (spec.class === CIPHER) {
    const from = parent.spec.args, to = spec.args;
    if (spec.method === 'getInstance')
      return from[1] === STRING && to[1] === 'java.security.Provider' && outer[0] === args[0];
    return spec.method === 'init' && to.length === from.length + 1
      && to[to.length - 1] === 'java.security.SecureRandom' && outer[0] === args[0]
      && from.slice(1).every((type, i) => type === to[i + 1] && sameObject(outer[i + 1], args[i + 1]));
  }
  if (spec.method === '$init') {
    const from = parent.spec.args[0], to = spec.args[0];
    if (spec.class !== 'java.io.FileOutputStream') {
      return from === STRING && to === FILE && outer.length === args.length
        && (outer.length === 1 || outer[1] === args[1]);
    }
    if (args.length !== 2 || args[1] !== (outer.length === 1 ? false : outer[1])) return false;
    if (from === STRING && to === FILE) return true;
    if (outer.length === 1 && from === to) {
      return from === STRING ? outer[0] === args[0] : sameObject(outer[0], args[0]);
    }
    return false;
  }
  if (spec.method === 'call') {
    return parent.spec.args[0] === URI && spec.args[0] === STRING
      && outer[0] != null && FRAMEWORK_URIS.has(outer[0].$className)
      && outer[0].getAuthority() === args[0] && outer[1] === args[1]
      && outer[2] === args[2] && sameObject(outer[3], args[3]);
  }
  if (!sameObject(outer[0], args[0])) return false;
  if (spec.method === 'openFileDescriptor')
    return outer.length === 2 && args.length === 3 && outer[1] === args[1] && args[2] == null;
  if (spec.method === 'openOutputStream')
    return outer.length === 1 && args.length === 2 && args[1] === 'w';
  if (spec.method === 'openTypedAssetFileDescriptor')
    return outer.length === 3 && args.length === 4 && outer[1] === args[1]
      && sameObject(outer[2], args[2]) && args[3] == null;
  if (spec.method === 'insert')
    return outer.length === 2 && args.length === 3 && sameObject(outer[1], args[1]) && args[2] == null;
  if (spec.method === 'update')
    return outer.length === 4 && spec.args[2] === 'android.os.Bundle' && sameObject(outer[1], args[1]);
  if (spec.method === 'delete')
    return outer.length === 3 && spec.args[1] === 'android.os.Bundle';
  if (spec.method !== 'query' || !sameObject(outer[1], args[1])) return false;
  if (outer.length === 5 && args.length === 6)
    return outer[2] === args[2] && sameObject(outer[3], args[3]) && outer[4] === args[4] && args[5] == null;
  return outer.length === 6 && args.length === 4
    && spec.args[2] === 'android.os.Bundle' && sameObject(outer[5], args[3]);
}

function createMonitor(Java, sendMessage, schedule) {
  const installed = new Map();
  const forwardingFrames = new Map();
  let revision = -1, queue = [], dropped = 0, sequence = 0, inspecting = false;
  let stopped = false, activeCalls = 0;
  function safe(fn, fallback) { try { return fn(); } catch (_) { return fallback; } }
  function textValue(type, text, limit = 2048) {
    return { type: type, value: text.slice(0, limit), truncated: text.length > limit };
  }
  function urlDestination(url) {
    const scheme = url.getProtocol();
    if (scheme !== 'http' && scheme !== 'https') return textValue(URL_CLASS, scheme + ':');
    // These getters read stored fields. URL.toExternalForm and getDefaultPort
    // delegate to the URL's handler, which may belong to the application.
    const port = url.getPort();
    const authority = url.getHost() + (port === -1 ? '' : ':' + port);
    return textValue(URL_CLASS, scheme + '://' + authority + (url.getPath() || ''));
  }
  function value(v, type) {
    if (v === null || v === undefined) return { type: type, value: null };
    if (type === URI && FRAMEWORK_URIS.has(v.$className))
      return textValue(type, String(v.toString()));
    // getPath() on a framework File returns its stored path, without disk I/O.
    if (type === FILE && v.$className === FILE)
      return textValue(type, String(v.getPath()));
    // Android's UnixPath stringifies its stored path. App Path providers stay opaque.
    if (type === PATH && v.$className === 'sun.nio.fs.UnixPath')
      return textValue(type, String(v.toString()));
    if (type === SOCKET_ADDRESS && v.$className === INET_SOCKET_ADDRESS) {
      const endpoint = Java.cast(v, Java.use(INET_SOCKET_ADDRESS));
      const host = endpoint.getHostString();
      const address = host.includes(':') && !host.startsWith('[') ? '[' + host + ']' : host;
      return textValue(INET_SOCKET_ADDRESS, address + ':' + endpoint.getPort());
    }
    if (type === 'long' && typeof Int64 !== 'undefined' && v instanceof Int64)
      return { type: type, value: v.toString() };
    if (type === 'java.lang.String' || type === 'char' || typeof v === 'string') {
      return textValue(type, String(v));
    }
    if (typeof v === 'boolean' || typeof v === 'number')
      return { type: type, value: typeof v === 'number' && !Number.isFinite(v) ? String(v) : v };
    return { type: type, opaque: true };
  }
  function sqlBinding(binding) {
    if (binding == null) return { type: 'null', value: null };
    if (typeof binding === 'string') return textValue(STRING, binding, 512);
    const type = binding.$className || 'java.lang.Object';
    if (!SQL_BOXED_SCALARS.has(type)) return { type: type, opaque: true };
    // Only final framework scalars are stringified. Keep Long's decimal
    // representation intact rather than rounding it through a JS number.
    return textValue(type, String(binding.toString()), 512);
  }
  function argumentValue(spec, args, index) {
    const type = spec.args[index], arg = args[index];
    if (spec.class === ANDROID_LOG && type === 'java.lang.Throwable' && arg != null)
      return { type: arg.$className || type, opaque: true };
    if (spec.class === CIPHER && spec.method === 'init' && index > 0 && arg != null)
      return { type: arg.$className || type, opaque: true };
    if (spec.class === FILES && type === COPY_OPTIONS && Array.isArray(arg)) {
      const items = arg.slice(0, 8).map(option => safe(() => {
        if (option == null) return { type: 'null', value: null };
        const optionType = option.$className || 'java.nio.file.CopyOption';
        return COPY_OPTION_TYPES.has(optionType)
          ? textValue(optionType, String(Java.cast(option, Java.use(optionType)).name()))
          : { type: optionType, opaque: true };
      }, { captureError: true }));
      return { type: type, items: items, count: arg.length };
    }
    const bindings = spec.class === SQLITE && (
      (spec.method === 'execSQL' && index === 1 && type === '[Ljava.lang.Object;')
      || (spec.method === 'rawQueryWithFactory' && index === 2 && type === '[Ljava.lang.String;')
    );
    if (!bindings || !Array.isArray(arg)) return value(arg, type);
    const items = arg.slice(0, 16).map(binding => safe(() => sqlBinding(binding), { captureError: true }));
    return { type: type, items: items, count: arg.length };
  }
  function inspect(fn) {
    inspecting = true;
    try { return safe(fn, { captureError: true }); } finally { inspecting = false; }
  }
  function emit(event) {
    if (queue.length >= MAX_QUEUED_EVENTS) { dropped++; return; }
    queue.push(event);
  }
  function captureCall(method, receiver, args, specs, thread) {
    if (!specs.length) return method.apply(receiver, args);
    if (queue.length >= MAX_QUEUED_EVENTS) { dropped++; return method.apply(receiver, args); }
    activeCalls++;
    try {
      return recordCall(method, receiver, args, specs, thread);
    } finally {
      activeCalls--;
    }
  }
  function recordCall(method, receiver, args, specs, thread) {
    const event = { id: ++sequence, time: Date.now(), revision: revision,
      profiles: specs.map(s => s.profileName),
      class: specs[0].class, method: specs[0].method, types: specs[0].args,
      thread: thread === null ? 'unknown' : String(thread) };
    if (specs.some(s => s.captureArguments)) {
      event.arguments = specs[0].args.map((_, i) => inspect(() => argumentValue(specs[0], args, i)));
      if (event.class === URL_CLASS && event.method === 'openConnection')
        event.destination = inspect(() => urlDestination(receiver));
      if (event.class === CIPHER && event.method === 'init')
        event.transformation = inspect(() => value(receiver.getAlgorithm(), STRING));
      if (event.class === FILE && (event.method === 'delete' || event.method === 'renameTo'))
        event.sourcePath = inspect(() => value(receiver, FILE));
    }
    if (specs.some(s => s.captureStack))
      event.stack = inspect(() => Java.backtrace({ limit: 16 }).frames.map(f => f.signature));
    let result;
    try { result = method.apply(receiver, args); }
    catch (error) {
      event.outcome = 'exception';
      const type = inspect(() => error.$className || (error.$h && Java.vm.getEnv().getObjectClassName(error.$h)));
      event.exception = { type: typeof type === 'string' ? type : 'unknown', opaque: true };
      if (!stopped) emit(event);
      throw error;
    }
    event.outcome = 'returned';
    if (specs.some(s => s.captureReturn))
      event.result = inspect(() => value(result, method.returnType.className));
    if (!stopped) emit(event);
    return result;
  }
  schedule(function () {
    if (!queue.length && !dropped) return;
    const batch = queue.splice(0, 32), lost = dropped;
    dropped = 0;
    try { sendMessage({ noxenEvent: 'monitor_batch', events: batch, dropped: lost }); }
    catch (_) { dropped += batch.length + lost; }
  }, 100);
  function configure(hooks, nextRevision) {
    if (stopped) return false;
    revision = nextRevision;
    Java.perform(function () {
      if (stopped || nextRevision !== revision) return;
      installed.forEach(record => { record.specs = []; });
      const statuses = [];
      hooks.forEach(spec => {
        const status = { profile: spec.profile, index: spec.index, state: 'Error', detail: '' };
        try {
          let klass, method;
          try {
            klass = Java.use(spec.class);
            method = klass[spec.method].overload.apply(klass[spec.method], spec.args);
          } catch (error) {
            status.state = 'Not found';
            throw error;
          }
          const key = String(method.handle);
          let record = installed.get(key);
          if (!record) {
            if (installed.size >= 128) throw new Error('Session hook limit reached; reconnect to install other methods');
            if (method.implementation !== null) throw new Error('Method already hooked; Intercept or extra-script conflict');
            record = { specs: [], method: method };
            record.wrapper = function () {
              if (stopped || inspecting || !record.specs.length) return method.apply(this, arguments);
              const specs = record.specs;
              const thread = safe(() => Process.getCurrentThreadId(), null);
              const builtin = specs.find(s =>
                (s.profile === 'content-provider' && s.class === RESOLVER)
                || (s.profile === 'file' && s.method === '$init' && FILE_CONSTRUCTORS.has(s.class))
                || (s.profile === 'crypto' && s.class === CIPHER));
              if (!builtin || thread === null)
                return captureCall(method, this, arguments, specs, thread);
              const parent = forwardingFrames.get(thread);
              const forwarded = inspect(() => forwardsTo(parent, builtin, this, arguments)) === true;
              const active = forwarded ? specs.filter(s => s !== builtin) : specs;
              forwardingFrames.set(thread, { spec: builtin, receiver: this, args: arguments });
              try {
                return captureCall(method, this, arguments, active, thread);
              } finally {
                if (parent) forwardingFrames.set(thread, parent);
                else forwardingFrames.delete(thread);
              }
            };
            method.implementation = record.wrapper;
            record.replacement = method.implementation;
            installed.set(key, record);
          } else if (record.method.implementation !== record.replacement) {
            throw new Error('Monitor hook was replaced by another script');
          }
          record.specs.push(spec);
          status.state = 'Active';
        } catch (e) { status.detail = String(e).slice(0, 512); }
        statuses.push(status);
      });
      sendMessage({ noxenEvent: 'monitor_status', revision: nextRevision, statuses: statuses });
    });
    return true;
  }
  function stop() {
    stopped = true;
    const final = { noxenEvent: 'monitor_batch', events: queue, dropped, incomplete: activeCalls > 0 };
    queue = [];
    dropped = 0;
    return final;
  }
  return { configure, stop };
}
module.exports = { createMonitor };
