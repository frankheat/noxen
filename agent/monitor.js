// Passive, bounded Monitor. Unknown objects are never stringified or traversed.
const MAX_QUEUED_EVENTS = 512;
const RESOLVER = 'android.content.ContentResolver';
const TRANSPORT = 'android.content.ContentProvider$Transport';
const ATTRIBUTION_SOURCE = 'android.content.AttributionSource';
const BUNDLE = 'android.os.Bundle';
const QUERY_ARGUMENT = 'android:query-arg-sql-';
const SQL_ARGUMENT_METHODS = new Set(['query', 'update', 'delete']);
const SQLITE = 'android.database.sqlite.SQLiteDatabase';
const ANDROID_LOG = 'android.util.Log';
const CIPHER = 'javax.crypto.Cipher';
const RUNTIME = 'java.lang.Runtime';
const PROCESS_BUILDER = 'java.lang.ProcessBuilder';
const IN_MEMORY_DEX = 'dalvik.system.InMemoryDexClassLoader';
const BYTE_BUFFER = 'java.nio.ByteBuffer';
const BYTE_BUFFERS = '[Ljava.nio.ByteBuffer;';
const MAX_DEX_BUFFERS = 8;
const WEB_VIEW = 'android.webkit.WebView';
const WEB_SETTINGS = 'android.webkit.WebSettings';
const WEB_SETTING_TYPES = {
  setJavaScriptEnabled: 'boolean',
  setAllowFileAccess: 'boolean',
  setAllowContentAccess: 'boolean',
  setAllowFileAccessFromFileURLs: 'boolean',
  setAllowUniversalAccessFromFileURLs: 'boolean',
  setMixedContentMode: 'int',
};
const WEB_LOAD_METHODS = new Set(['loadUrl', 'postUrl', 'loadData', 'loadDataWithBaseURL']);
const MAX_TRACKED_WEB_VIEWS = 128;
const URL_CLASS = 'java.net.URL';
const SOCKET_ADDRESS = 'java.net.SocketAddress';
const INET_SOCKET_ADDRESS = 'java.net.InetSocketAddress';
const URI = 'android.net.Uri';
const INTENT = 'android.content.Intent';
const COMPONENT_NAME = 'android.content.ComponentName';
const CLASS = 'java.lang.Class';
const STRING = 'java.lang.String';
const STRINGS = '[Ljava.lang.String;';
const MAX_PROCESS_ARGUMENTS = 32;
const PROCESS_LIST_TYPES = new Set([
  'java.util.ArrayList', 'java.util.Arrays$ArrayList',
  'java.util.Collections$EmptyList', 'java.util.Collections$SingletonList',
]);
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

function isWebSetting(spec) {
  return spec.profile === 'webview' && spec.class === WEB_SETTINGS && spec.args.length === 1
    && Object.prototype.hasOwnProperty.call(WEB_SETTING_TYPES, spec.method)
    && WEB_SETTING_TYPES[spec.method] === spec.args[0];
}

function webObservationKey(hooks) {
  if (!hooks.some(s => s.profile === 'webview' && s.class === WEB_VIEW
      && s.method === 'getSettings' && !s.args.length)) return '';
  return hooks.filter(isWebSetting).map(s => s.method + ':' + s.captureArguments).sort().join(',');
}

function isProcessExecution(spec) {
  return spec.profile === 'process-execution'
    && ((spec.class === RUNTIME && spec.method === 'exec'
      && (spec.args[0] === STRING || spec.args[0] === STRINGS) && spec.args.length <= 3
      && (spec.args.length < 2 || spec.args[1] === STRINGS)
      && (spec.args.length < 3 || spec.args[2] === FILE))
      || (spec.class === PROCESS_BUILDER && spec.method === 'start' && !spec.args.length));
}

function commandString(value) {
  if (typeof value === 'string' || value == null) return value;
  return value.$className === STRING ? String(value.toString()) : undefined;
}

function builderCommand(builder) {
  const list = builder.command();
  return list && PROCESS_LIST_TYPES.has(list.$className) ? list : null;
}

function processForwardsTo(parent, spec, receiver, args) {
  if (parent.spec.class !== RUNTIME) return false;
  const outer = parent.args;
  const inputType = parent.spec.args[0];
  if (spec.class === RUNTIME) {
    if (args.length !== 3 || !sameObject(parent.receiver, receiver)) return false;
    if (!sameObject(outer[1] ?? null, args[1]) || !sameObject(outer[2] ?? null, args[2])) return false;
    // Runtime's string overload tokenizes before dispatching to the vector overload.
    if (inputType === STRING && spec.args[0] === STRINGS) return true;
    return outer.length < 3 && inputType === spec.args[0] && sameObject(outer[0], args[0]);
  }
  if (inputType !== STRINGS || outer.length !== 3 || !Array.isArray(outer[0])) return false;
  const list = builderCommand(receiver);
  if (!list || !sameObject(outer[2], receiver.directory())) return false;
  const count = list.size();
  if (count !== outer[0].length) return false;
  // The framework constructs this builder directly from the vector. Check a
  // bounded prefix as well, so a different nested start is recorded separately.
  for (let i = 0; i < Math.min(count, MAX_PROCESS_ARGUMENTS); i++) {
    const element = commandString(list.get(i));
    if (element === undefined || element !== commandString(outer[0][i])) return false;
  }
  return true;
}

// Match only known overload forwarding on the same Java object. Nested calls
// keep their own frame, even when their built-in event is folded.
function forwardsTo(parent, spec, receiver, args) {
  if (!parent || parent.spec.profile !== spec.profile) return false;
  if (isProcessExecution(spec)) return processForwardsTo(parent, spec, receiver, args);
  if (parent.spec.class !== spec.class || !sameObject(parent.receiver, receiver)) return false;
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
  if (spec.class === IN_MEMORY_DEX) {
    if (spec.args[0] !== BYTE_BUFFERS || outer.length !== 2
        || !sameObject(outer[1], args[args.length - 1])
        || (args.length === 3 && args[1] != null)) return false;
    if (parent.spec.args[0] === BYTE_BUFFER)
      return Array.isArray(args[0]) && args[0].length === 1 && sameObject(outer[0], args[0][0]);
    return args.length === 3 && sameObject(outer[0], args[0]);
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

function createMonitor(Java, sendMessage, schedule, captureStamp = () => ({ time: Date.now() })) {
  const installed = new Map();
  const forwardingFrames = new Map();
  const inspectionDepth = new Map();
  let requestedRevision = -1, revision = -1, queue = [], dropped = 0, sequence = 0;
  let stopped = false, activeCalls = 0;
  let webViews = [], webSettingsHooks = [], statuses = [], webViewId = 0;
  let webObservation = '', webGeneration = 0;
  let javaSystem, weakReference;
  let javaBuffer, javaBinder, javaArray;
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
  function strings(array) {
    return { type: STRINGS, items: array.slice(0, 16).map(sqlBinding), count: array.length };
  }
  function providerArgument(spec, arg, type) {
    if (arg == null) return value(arg, type);
    if (type === ATTRIBUTION_SOURCE && arg.$className === type) {
      const packageName = arg.getPackageName();
      return packageName == null ? value(null, type) : textValue(type, String(packageName));
    }
    if (type === STRINGS && Array.isArray(arg)) return strings(arg);
    return value(arg, type);
  }
  function providerQueryArguments(bundle) {
    const opaque = { type: BUNDLE, opaque: true };
    // Inspect only the materialized map. Bundle getters can unpack a Parcel
    // or resolve an individual lazy value on newer Android versions.
    if (bundle.$className !== BUNDLE || bundle.isParcelled() !== false) return opaque;
    const map = bundle.mMap.value;
    if (map == null) return opaque;
    function read(key, type) {
      const name = QUERY_ARGUMENT + key;
      const raw = map.get(name);
      if (raw == null) return value(null, type);
      if (typeof raw === 'string' && type === STRING) return value(raw, type);
      if (String(raw.getClass().getName()) !== type) return { type: type, opaque: true };
      if (type === STRING) return value(raw, type);
      javaArray ??= Java.use('java.lang.reflect.Array');
      const count = javaArray.getLength(raw);
      const items = [];
      for (let i = 0; i < Math.min(count, 16); i++) {
        const item = javaArray.get(raw, i);
        items.push(item == null ? value(null, 'null') : textValue(STRING, String(item), 512));
      }
      return { type: STRINGS, items, count };
    }
    return { type: BUNDLE, queryArguments: {
      selection: read('selection', STRING),
      selectionArgs: read('selection-args', STRINGS),
      sortOrder: read('sort-order', STRING),
    } };
  }
  function argumentValue(spec, args, index) {
    const type = spec.args[index], arg = args[index];
    if (spec.class === TRANSPORT) return providerArgument(spec, arg, type);
    if (spec.class === INTENT && arg != null && arg.$className === type) {
      if (spec.method === 'setComponent' && type === COMPONENT_NAME)
        return textValue(type, String(Java.cast(arg, Java.use(type)).flattenToString()));
      if (spec.method === 'getParcelableExtra' && type === CLASS)
        return textValue(type, String(Java.cast(arg, Java.use(type)).getName()));
    }
    if (spec.class === IN_MEMORY_DEX && spec.method === '$init' && index === 0) {
      if (type === BYTE_BUFFER) return dexBuffer(arg);
      if (type === BYTE_BUFFERS && Array.isArray(arg)) {
        const items = arg.slice(0, MAX_DEX_BUFFERS).map(buffer =>
          safe(() => dexBuffer(buffer), { type: BYTE_BUFFER, captureError: true }));
        return { type: type, items: items, count: arg.length };
      }
    }
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
  function binder() {
    return javaBinder ??= Java.use('android.os.Binder');
  }
  function dexBuffer(buffer) {
    if (buffer == null) return { type: BYTE_BUFFER, value: null };
    // Buffer.remaining() is final and reads position and limit without changing either.
    javaBuffer ??= Java.use('java.nio.Buffer');
    return { type: BYTE_BUFFER, remainingBytes: Java.cast(buffer, javaBuffer).remaining() };
  }
  function processArguments(event, receiver, args) {
    function vector(count, get) {
      const items = [];
      for (let i = 0; i < Math.min(count, MAX_PROCESS_ARGUMENTS); i++) {
        items.push(safe(() => {
          const item = commandString(get(i));
          if (item === undefined) return { type: STRING, opaque: true };
          return item === null ? { type: STRING, value: null } : textValue(STRING, item, 512);
        }, { type: STRING, captureError: true }));
      }
      return { type: STRINGS, items: items, count: count };
    }
    const commandType = event.types[0];
    if (event.class === RUNTIME) {
      event.processCommand = inspect(() => commandType === STRINGS && Array.isArray(args[0])
        ? vector(args[0].length, index => args[0][index]) : value(args[0], commandType));
      event.workingDirectory = inspect(() => value(args[2], FILE));
    } else {
      event.processCommand = inspect(() => {
        const command = builderCommand(receiver);
        return command ? vector(command.size(), index => command.get(index)) : { type: STRINGS, opaque: true };
      });
      event.workingDirectory = inspect(() => value(receiver.directory(), FILE));
    }
  }
  function withoutRecording(fn) {
    const thread = safe(() => Process.getCurrentThreadId(), null);
    const depth = inspectionDepth.get(thread) || 0;
    inspectionDepth.set(thread, depth + 1);
    try {
      return fn();
    } finally {
      if (depth) inspectionDepth.set(thread, depth);
      else inspectionDepth.delete(thread);
    }
  }
  function inspect(fn) {
    return withoutRecording(() => safe(fn, { captureError: true }));
  }
  function objectHash(object) {
    javaSystem ??= Java.use('java.lang.System');
    return javaSystem.identityHashCode(object);
  }
  function weakIdentity(object, hash) {
    weakReference ??= Java.use('java.lang.ref.WeakReference');
    return { hash: hash, ref: weakReference.$new(object) };
  }
  function matchesIdentity(identity, object, hash) {
    return identity && identity.hash === hash && sameObject(identity.ref.get(), object);
  }
  function findWebView(receiver) {
    const hash = objectHash(receiver);
    let view = webViews.find(entry => matchesIdentity(entry, receiver, hash));
    if (!view) {
      view = { ...weakIdentity(receiver, hash), id: ++webViewId, settings: null };
      if (webViews.length === MAX_TRACKED_WEB_VIEWS) webViews.shift();
      webViews.push(view);
    }
    return view;
  }
  function matchingWebSettings(receiver, hash) {
    return webViews.filter(view => matchesIdentity(view.settings, receiver, hash));
  }
  function publishStatus() {
    sendMessage({ noxenEvent: 'monitor_status', revision: revision, statuses: statuses });
  }
  function observeWebResult(spec, receiver, args, result, generation) {
    if (!spec || stopped || generation !== webGeneration) return;
    inspect(() => {
      if (spec.class === WEB_VIEW && spec.method === 'getSettings' && result != null) {
        const view = findWebView(receiver);
        const hash = objectHash(result);
        if (matchesIdentity(view.settings, result, hash)) return;
        const [existing] = matchingWebSettings(result, hash);
        view.settings = existing?.settings ?? { ...weakIdentity(result, hash), values: {} };
        if (existing) return;
        const implementation = result.getClass();
        const className = String(implementation.getName());
        const loader = implementation.getClassLoader();
        const factory = loader == null ? Java : Java.ClassFactory.get(loader);
        let changed = false;
        for (const { spec: setting, status } of webSettingsHooks) {
          const resolved = { ...status };
          installHook(setting, resolved, factory, className);
          if (status.state === 'Active' || (status.state === resolved.state && status.detail === resolved.detail))
            continue;
          Object.assign(status, resolved);
          changed = true;
        }
        if (changed) publishStatus();
      } else if (isWebSetting(spec) && spec.captureArguments) {
        const [view] = matchingWebSettings(receiver, objectHash(receiver));
        if (view && (typeof args[0] === 'boolean' || Number.isInteger(args[0])))
          view.settings.values[spec.method] = args[0];
      }
    });
  }
  function annotateWebEvent(event, spec, receiver) {
    if (!spec) return;
    inspect(() => {
      if (spec.class === WEB_VIEW) {
        const view = findWebView(receiver);
        event.webViewId = view.id;
        if (WEB_LOAD_METHODS.has(spec.method)) event.webViewSettings = { ...view.settings?.values };
      } else {
        const matches = matchingWebSettings(receiver, objectHash(receiver));
        if (matches.length === 1) event.webViewId = matches[0].id;
      }
    });
  }
  function emit(event) {
    if (queue.length >= MAX_QUEUED_EVENTS) { dropped++; return; }
    queue.push(event);
  }
  function captureCall(method, receiver, args, specs, thread) {
    if (!specs.length) return method.apply(receiver, args);
    let trace = null;
    const needsTrace = specs.some(s => s.captureStack || s.callerFilter);
    if (needsTrace) {
      const depth = Math.max(...specs.map(s => s.stackDepth || 16));
      trace = inspect(() => Java.backtrace({ limit: depth }).frames);
      specs = specs.filter(spec => {
        if (!spec.callerFilter || !Array.isArray(trace)) return true;
        const frames = trace.slice(0, spec.stackDepth || 16);
        // Frida includes the hooked method as the first frame.
        if (frames[0]?.className === spec.class && frames[0]?.methodName === spec.method) frames.shift();
        const candidates = spec.callerMatch === 'anywhere' ? frames : frames.slice(0, 1);
        const pattern = spec.callerFilter.split('').map(char => {
          if (char === '*') return '.*';
          if (char === '?') return '.';
          return char.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        }).join('');
        const matcher = new RegExp('^' + pattern + '$');
        return candidates.some(frame => matcher.test(frame.className + '.' + frame.methodName));
      });
      if (!specs.length) return method.apply(receiver, args);
    }
    const webSpec = webSettingsHooks.length ? specs.find(spec =>
      (spec.profile === 'webview' && spec.class === WEB_VIEW) || isWebSetting(spec)) : null;
    if (queue.length >= MAX_QUEUED_EVENTS) {
      dropped++;
      const generation = webGeneration;
      const result = method.apply(receiver, args);
      observeWebResult(webSpec, receiver, args, result, generation);
      return result;
    }
    activeCalls++;
    try {
      return recordCall(method, receiver, args, specs, thread, webSpec, trace);
    } finally {
      activeCalls--;
    }
  }
  function recordCall(method, receiver, args, specs, thread, webSpec, trace) {
    const generation = webGeneration;
    const event = { ...captureStamp(), id: ++sequence, revision: revision,
      profiles: specs.map(s => s.profileName),
      class: specs[0].class, method: specs[0].method, types: specs[0].args,
      thread: thread === null ? 'unknown' : String(thread) };
    annotateWebEvent(event, webSpec, receiver);
    if (event.class === TRANSPORT) {
      // Transport is the Binder entry point shared by every provider in the process.
      event.provider = inspect(() => textValue(STRING, String(receiver.this$0.value.getClass().getName())));
      event.callingUid = inspect(() => ({ type: 'int', value: binder().getCallingUid() }));
    }
    if (specs.some(s => s.captureArguments) && specs.some(isProcessExecution)) {
      processArguments(event, receiver, args);
    } else if (specs.some(s => s.captureArguments)) {
      event.arguments = specs[0].args.map((_, i) => inspect(() => argumentValue(specs[0], args, i)));
      if (event.class === STRING
          && ['equals', 'equalsIgnoreCase', 'startsWith', 'endsWith', 'contains'].includes(event.method)) {
        event.receiver = inspect(() => value(receiver, STRING));
        event.arguments[0] = inspect(() => {
          const arg = args[0];
          if (arg != null && (typeof arg === 'string' || arg.$className === STRING))
            return value(typeof arg === 'string' ? arg : Java.cast(arg, Java.use(STRING)), STRING);
          return value(arg, arg == null ? event.types[0] : arg.$className || event.types[0]);
        });
      }
      if (event.class === URL_CLASS && event.method === 'openConnection')
        event.destination = inspect(() => urlDestination(receiver));
      if (event.class === CIPHER && event.method === 'init')
        event.transformation = inspect(() => value(receiver.getAlgorithm(), STRING));
      if (event.class === FILE && (event.method === 'delete' || event.method === 'renameTo'))
        event.sourcePath = inspect(() => value(receiver, FILE));
    }
    if (specs.some(s => s.callerFilter) && !Array.isArray(trace)) event.callerFilterError = true;
    if (specs.some(s => s.captureStack)) {
      const depth = Math.max(...specs.filter(s => s.captureStack).map(s => s.stackDepth || 16));
      event.stack = Array.isArray(trace) ? trace.slice(0, depth).map(f => f.signature) : trace;
      if (Array.isArray(trace) && trace.length >= depth) event.stackTruncated = true;
    }
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
    if (event.class === TRANSPORT && event.arguments && SQL_ARGUMENT_METHODS.has(event.method)) {
      const index = event.types.indexOf(BUNDLE);
      if (index >= 0 && args[index] != null) {
        event.arguments[index] = withoutRecording(() =>
          safe(() => providerQueryArguments(args[index]), event.arguments[index]));
      }
    }
    observeWebResult(webSpec, receiver, args, result, generation);
    if (specs.some(s => s.captureReturn))
      event.result = inspect(() => {
        const type = method.returnType.className;
        if (event.class === INTENT && event.method === 'getParcelableExtra' && result != null)
          return { type: result.$className || type, opaque: true };
        return value(result, type);
      });
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
  function installHook(spec, status, factory = Java, className = spec.class) {
    try {
      let klass, method;
      try {
        klass = factory.use(className);
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
          if (stopped || !record.specs.length) return method.apply(this, arguments);
          const specs = record.specs;
          const thread = safe(() => Process.getCurrentThreadId(), null);
          if (inspectionDepth.has(thread)) return method.apply(this, arguments);
          const builtin = specs.find(s =>
            (s.profile === 'content-provider' && s.class === RESOLVER)
            || (s.profile === 'file' && s.method === '$init' && FILE_CONSTRUCTORS.has(s.class))
            || (s.profile === 'crypto' && s.class === CIPHER)
            || (s.profile === 'dynamic-code-loading' && s.class === IN_MEMORY_DEX && s.method === '$init')
            || isProcessExecution(s));
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
      }
      enableInstalledHook(record, spec, status);
    } catch (e) { status.detail = String(e).slice(0, 512); }
  }
  function enableInstalledHook(record, spec, status) {
    if (record.method.implementation !== record.replacement)
      throw new Error('Monitor hook was replaced by another script');
    if (!record.specs.includes(spec)) record.specs.push(spec);
    status.state = 'Active';
    status.detail = '';
  }

  function configure(hooks, nextRevision) {
    if (stopped) return false;
    requestedRevision = nextRevision;
    Java.perform(function () {
      if (stopped || nextRevision !== requestedRevision) return;
      revision = nextRevision;
      const nextObservation = webObservationKey(hooks);
      const preserveWebViews = nextObservation && nextObservation === webObservation;
      const webRecords = new Map();
      if (!preserveWebViews) {
        webViews = [];
        webGeneration++;
      }
      webObservation = nextObservation;
      for (const record of installed.values()) {
        if (preserveWebViews) {
          for (const spec of record.specs) {
            if (!isWebSetting(spec)) continue;
            if (!webRecords.has(spec.method)) webRecords.set(spec.method, []);
            webRecords.get(spec.method).push(record);
          }
        }
        record.specs = [];
      }
      webSettingsHooks = [];
      statuses = hooks.map(spec => {
        const status = { profile: spec.profile, index: spec.index, state: 'Error', detail: '' };
        if (isWebSetting(spec)) {
          status.state = 'Pending';
          status.detail = 'Waiting for WebView.getSettings() to reveal the concrete settings class';
          webSettingsHooks.push({ spec: spec, status: status });
          for (const record of webRecords.get(spec.method) || []) {
            try {
              enableInstalledHook(record, spec, status);
            } catch (error) {
              if (status.state !== 'Active') {
                status.state = 'Error';
                status.detail = String(error).slice(0, 512);
              }
            }
          }
        } else {
          installHook(spec, status);
        }
        return status;
      });
      publishStatus();
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
  return { configure, stop, withoutRecording };
}
module.exports = { createMonitor };
