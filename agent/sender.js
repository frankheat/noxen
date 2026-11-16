// Explicit calls from the selected application's own context. No hooks installed.
function createSender(withoutRecording = fn => fn()) {
  let active = null;
  let workerClass = null;
  let serial = 0;
  let receiverClass = null;
  const J = () => globalThis.Java;
  const use = name => J().use(name);
  const javaText = value => value === null || value === undefined ? null :
    value.includes('\u0000') ? use('java.lang.String').$new(J().array('char', value.split(''))) : value;
  const uri = value => value === null || value === undefined ? null : use('android.net.Uri').parse(javaText(value));
  const strings = value => value === null || value === undefined ? null : J().array('java.lang.String', value.map(javaText));
  const context = () => {
    const app = use('android.app.ActivityThread').currentApplication();
    if (app === null) throw new Error('Application context is not ready; open the sender app first');
    return app.getApplicationContext();
  };
  const text = value => value === null ? null : String(value);
  const jsonSize = value => JSON.stringify(value).replace(/[\u007f-\uffff]/g,
    c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).length;

  function identitySnapshot() {
    return withoutRecording(() => {
        const c = context(), a = c.getApplicationInfo();
        const p = c.getPackageManager().getPackageInfo(c.getPackageName(), 0x1000);
        const permissions = [];
        const names = p.requestedPermissions.value;
        const flags = p.requestedPermissionsFlags.value;
        if (names !== null) for (let i = 0; i < names.length; i++) {
          permissions.push({name: String(names[i]), granted: !!(flags[i] & 2)});
        }
        const uid = use('android.os.Process').myUid();
        const shared = c.getPackageManager().getPackagesForUid(uid);
        return {package: String(c.getPackageName()), uid, observedAt: Date.now(),
          pid: use('android.os.Process').myPid(), targetSdk: a.targetSdkVersion.value,
          sdk: use('android.os.Build$VERSION').SDK_INT.value, systemApp: !!(a.flags.value & 1),
          version: text(p.versionName.value), permissions,
          packagesForUid: shared === null ? [] : Array.from(shared, String)};
    });
  }

  function identity() {
    return new Promise((resolve, reject) => J().perform(() => {
      try { resolve(identitySnapshot()); } catch (error) { reject(error); }
    }));
  }

  function activityContext() {
    return withoutRecording(() => {
      try {
        const sdk = use('android.os.Build$VERSION').SDK_INT.value;
        if (sdk < 29) return {state: 'not_applicable'};
        const ProcessInfo = use('android.app.ActivityManager$RunningAppProcessInfo');
        const info = ProcessInfo.$new();
        use('android.app.ActivityManager').getMyMemoryState(info);
        const importance = info.importance.value;
        if (importance <= 0 || importance >= ProcessInfo.IMPORTANCE_GONE.value) return {state: 'unknown'};
        const visible = ProcessInfo.IMPORTANCE_VISIBLE.value;
        let state = 'unknown';
        if (importance > visible) state = 'background';
        if (importance === visible || importance === ProcessInfo.IMPORTANCE_FOREGROUND.value) {
          state = 'foreground_or_visible';
        }
        return {
          state,
          importance,
          sampledAt: Date.now(),
        };
      } catch (_) {
        return {state: 'unknown'};
      }
    });
  }

  function putValues(target, values, contentValues) {
    for (const rawKey of Object.keys(values || {})) {
      const item = values[rawKey], v = item.value, kind = item.type, key = javaText(rawKey);
      if (contentValues) {
        if (v === null) target.putNull(key);
        else {
          const classes = {String: 'java.lang.String', boolean: 'java.lang.Boolean', int: 'java.lang.Integer',
            long: 'java.lang.Long', double: 'java.lang.Double', float: 'java.lang.Float', short: 'java.lang.Short',
            byte: 'java.lang.Byte', 'byte[]': '[B'};
          const cls = classes[kind];
          if (!cls) throw new Error('Unsupported ContentValues type: ' + kind);
          const boxed = kind === 'String' ? javaText(v) : kind === 'byte[]' ? J().array('byte', v) : kind === 'long' ? use(cls).valueOf(String(v)) : use(cls).$new(v);
          target.put.overload('java.lang.String', cls).call(target, key, boxed);
        }
      } else if (kind === 'String') target.putString(key, javaText(v));
      else if (kind === 'boolean') target.putBoolean(key, v);
      else if (kind === 'int') target.putInt(key, v);
      else if (kind === 'long') target.putLong(key, new Int64(v));
      else if (kind === 'double') target.putDouble(key, v);
      else if (kind === 'float') target.putFloat(key, v);
      else if (kind === 'byte') target.putByte(key, v);
      else if (kind === 'short') target.putShort(key, v);
      else if (kind === 'char') target.putChar(key, v);
      else if (kind.endsWith('[]')) {
        const base = kind.slice(0, -2);
        const methods = {String: 'putStringArray', boolean: 'putBooleanArray', byte: 'putByteArray',
          short: 'putShortArray', int: 'putIntArray', long: 'putLongArray', float: 'putFloatArray',
          double: 'putDoubleArray', char: 'putCharArray', Intent: 'putParcelableArray'};
        const method = methods[base];
        if (!method) throw new Error('Unsupported array type');
        const type = base === 'String' ? 'java.lang.String' : base === 'Intent' ? 'android.content.Intent' : base;
        const values = v === null ? null : v.map(item => base === 'long' ? new Int64(item) : base === 'Intent' ? intent(item) : base === 'String' ? javaText(item) : item);
        target[method](key, values === null ? null : J().array(type, values));
      }
      else if (kind === 'Bundle') target.putBundle(key, bundle(v));
      else if (kind === 'Intent') target.putParcelable(key, intent(v));
      else if (kind === 'Uri') target.putParcelable(key, uri(v));
      else throw new Error('Unsupported extra type: ' + kind);
    }
    return target;
  }
  const bundle = values => values === null ? null : putValues(use('android.os.Bundle').$new(), values, false);

  function readBundle(value, depth = 0, budget = {remaining: 32768}) {
    if (value === null) return null;
    if (depth >= 4) return {captured: false, reason: 'depth limit'};
    const result = Object.create(null), keys = value.keySet().iterator();
    let count = 0;
    while (keys.hasNext()) {
      if (++count > 100 || budget.remaining <= 0) return {values: result, truncated: true};
      const key = String(keys.next());
      if (key.length > budget.remaining) return {values: result, truncated: true};
      budget.remaining -= key.length;
      try {
        const item = value.get(key);
        if (item === null) { result[key] = {type: 'null', value: null}; continue; }
        const type = String(item.getClass().getName());
        let converted;
        if (type === 'java.lang.String' || type === 'java.lang.Integer' || type === 'java.lang.Long' ||
            type === 'java.lang.Boolean' || type === 'java.lang.Double' || type === 'java.lang.Float') {
          const raw = String(item.toString());
          converted = {type, value: raw.slice(0, Math.max(0, Math.min(4096, budget.remaining))), truncated: raw.length > Math.min(4096, budget.remaining)};
        } else if (type === 'android.os.Bundle') converted = {type, value: readBundle(J().cast(item, use(type)), depth + 1, budget)};
        else converted = {type, captured: false};
        budget.remaining -= JSON.stringify(converted).length;
        result[key] = converted;
      } catch (error) { result[key] = {captured: false, error: String(error).slice(0, 512)}; }
    }
    return {values: result, truncated: false};
  }

  function intent(spec) {
    if (spec === null) return null;
    const result = use('android.content.Intent').$new();
    if (spec.component != null) {
      const component = use('android.content.ComponentName').unflattenFromString(javaText(spec.component));
      if (component === null) throw new Error('Invalid component');
      result.setComponent(component);
    }
    if (spec.package != null) result.setPackage(javaText(spec.package));
    if (spec.action !== undefined) result.setAction(javaText(spec.action));
    result.setDataAndType(uri(spec.data), javaText(spec.mimeType));
    result.setFlags((spec.flags || 0) | 0);
    for (const category of spec.categories || []) result.addCategory(javaText(category));
    if (spec.extras != null) result.putExtras.overload('android.os.Bundle').call(result, bundle(spec.extras));
    if (spec.selector != null) result.setSelector(intent(spec.selector));
    if (spec.clipData != null) {
      const clip = spec.clipData;
      const item = v => use('android.content.ClipData$Item').$new(
        v.text == null ? null : use('java.lang.String').$new(javaText(v.text)),
        javaText(v.htmlText), v.intent == null ? null : intent(v.intent), uri(v.uri));
      const data = use('android.content.ClipData').$new(
        clip.label == null ? null : use('java.lang.String').$new(javaText(clip.label)), strings(clip.mimeTypes), item(clip.items[0]));
      for (const v of clip.items.slice(1)) data.addItem(item(v));
      result.setClipData(data);
    }
    return result;
  }

  function query(resolver, request, signal) {
    const cursor = resolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String',
      '[Ljava.lang.String;', 'java.lang.String', 'android.os.CancellationSignal').call(resolver,
      uri(request.uri), strings(request.projection), javaText(request.selection),
      strings(request.selectionArgs), javaText(request.sortOrder), signal);
    if (cursor === null) return {kind: 'cursor', value: null};
    try {
      if (cursor.getColumnCount() > 256) return {kind: 'cursor', captured: false, truncated: true, reason: 'More than 256 columns'};
      const result = {kind: 'cursor', columns: Array.from(cursor.getColumnNames(), String), rows: [], truncated: false};
      let bytes = jsonSize(result);
      if (bytes > request.maxBytes) return {kind: 'cursor', rows: [], truncated: true, reason: 'Column names exceed the byte limit'};
      while (cursor.moveToNext()) {
        signal.throwIfCanceled();
        if (result.rows.length >= request.maxRows) { result.truncated = true; break; }
        const row = [];
        for (let i = 0; i < result.columns.length; i++) {
          const kind = cursor.getType(i);
          if (kind === 0) row.push({type: 'null', value: null});
          else if (kind === 1) row.push({type: 'long', value: cursor.getLong(i).toString()});
          else if (kind === 2) {
            const value = cursor.getDouble(i);
            row.push({type: 'double', value: Number.isFinite(value) ? value : String(value)});
          } else if (kind === 4) row.push({type: 'blob', captured: false});
          else {
            const s = cursor.getString(i);
            row.push({type: 'String', value: s === null ? null : String(s).slice(0, request.maxBytes),
              truncated: s !== null && String(s).length > request.maxBytes});
          }
        }
        // Conservatively account for JSON escaping and UTF-8.
        const cost = jsonSize(row) + 1;
        if (bytes + cost > request.maxBytes) { result.truncated = true; break; }
        bytes += cost;
        result.rows.push(row);
      }
      return result;
    } finally { cursor.close(); }
  }

  function perform(request, signal, run) {
    const c = context(), op = request.operation;
    if (request.intent) {
      const value = withoutRecording(() => intent(request.intent));
      if (op === 'startActivity') {
        run.activityContext = activityContext();
        c.startActivity(value);
        return {kind: 'void', activityLaunch: 'unverified'};
      }
      if (op === 'sendBroadcast') { c.sendBroadcast.overload('android.content.Intent', 'java.lang.String')
        .call(c, value, javaText(request.receiverPermission)); return {kind: 'void'}; }
      if (op === 'sendOrderedBroadcast') {
        return new Promise((resolve, reject) => {
          if (receiverClass === null) receiverClass = J().registerClass({
            name: 'dev.noxen.sender.ResultReceiver' + Date.now() + (++serial),
            superClass: use('android.content.BroadcastReceiver'),
            methods: {onReceive: [{returnType: 'void', argumentTypes: ['android.content.Context', 'android.content.Intent'],
              implementation() {
                const done = active && active.broadcastResolve;
                if (!done) return;
                const result = {kind: 'broadcastResult', code: this.getResultCode(), data: text(this.getResultData())};
                try { result.extras = withoutRecording(() => readBundle(this.getResultExtras(false))); }
                catch (error) { result.extras = {captured: false, error: String(error).slice(0, 512)}; }
                done(result);
              }}]},
          });
          active.broadcastResolve = resolve;
          active.receiver = receiverClass.$new();
          try {
            c.sendOrderedBroadcast.overload('android.content.Intent', 'java.lang.String', 'android.content.BroadcastReceiver',
              'android.os.Handler', 'int', 'java.lang.String', 'android.os.Bundle').call(c, value,
              javaText(request.receiverPermission), active.receiver,
              use('android.os.Handler').$new(use('android.os.Looper').getMainLooper()), 0, null, null);
          } catch (error) { reject(error); }
        });
      }
      if (op === 'stopService') return {kind: 'boolean', value: c.stopService(value)};
      if (op === 'startService' || op === 'startForegroundService') {
        const component = c[op](value);
        return {kind: 'component', value: component === null ? null : String(component.flattenToString())};
      }
      throw new Error('Unsupported Intent operation');
    }
    const r = c.getContentResolver(), u = uri(request.uri);
    if (op === 'query') return query(r, request, signal);
    if (op === 'getType') return {kind: 'String', value: text(r.getType(u))};
    if (op === 'insert') return {kind: 'uri', value: text(r.insert(u, withoutRecording(() => putValues(use('android.content.ContentValues').$new(), request.values, true))))};
    if (op === 'update') return {kind: 'int', value: r.update(u, withoutRecording(() => putValues(use('android.content.ContentValues').$new(), request.values, true)),
      javaText(request.selection), strings(request.selectionArgs))};
    if (op === 'delete') return {kind: 'int', value: r.delete(u, javaText(request.selection), strings(request.selectionArgs))};
    if (op === 'call') {
      const b = r.call.overload('android.net.Uri', 'java.lang.String', 'java.lang.String', 'android.os.Bundle')
        .call(r, u, javaText(request.method), javaText(request.arg), withoutRecording(() => bundle(request.extras == null ? null : request.extras)));
      if (b === null) return {kind: 'Bundle', value: null};
      return {kind: 'Bundle', value: withoutRecording(() => readBundle(b))};
    }
    if (op === 'openFileDescriptor') {
      const fd = r.openFileDescriptor.overload('android.net.Uri', 'java.lang.String', 'android.os.CancellationSignal')
        .call(r, u, 'r', signal);
      if (fd === null) return {kind: 'file', value: null};
      let stream = null;
      try {
        stream = use('android.os.ParcelFileDescriptor$AutoCloseInputStream').$new(fd);
        const buffer = J().array('byte', new Array(Math.min(8192, request.maxBytes + 1)).fill(0));
        const output = use('java.io.ByteArrayOutputStream').$new();
        let read = 0;
        while (read <= request.maxBytes) {
          signal.throwIfCanceled();
          const n = stream.read.overload('[B', 'int', 'int').call(stream, buffer, 0, Math.min(buffer.length, request.maxBytes + 1 - read));
          if (n === -1) break;
          output.write.overload('[B', 'int', 'int').call(output, buffer, 0, n);
          read += n;
        }
        const bytes = output.toByteArray();
        const limited = J().array('byte', Array.from(bytes).slice(0, request.maxBytes));
        return {kind: 'file', encoding: 'base64', value: String(use('android.util.Base64').encodeToString(limited, 2)),
          bytes: Math.min(read, request.maxBytes), truncated: read > request.maxBytes};
      } finally { if (stream !== null) stream.close(); else fd.close(); }
    }
    throw new Error('Unsupported provider operation');
  }

  function execute(request, jobId) {
    if (active !== null) return Promise.reject(new Error('Sender is busy'));
    const job = {request, jobId, signal: null, resolve: null, reject: null, cancelled: false};
    active = job;
    return new Promise((resolve, reject) => {
      job.resolve = resolve; job.reject = reject;
      J().perform(() => {
        try {
          if (workerClass === null) workerClass = J().registerClass({
            name: 'dev.noxen.sender.Worker' + Date.now() + (++serial),
            implements: [use('java.lang.Runnable')],
            methods: {run() {
              const current = active;
              if (current === null) return;
              const clock = use('android.os.SystemClock');
              const start = clock.elapsedRealtime();
              const result = {startedAt: Date.now(), state: 'returned'};
              function finish(value, error) {
                if (error) {
                  result.state = String(error).includes('android.os.OperationCanceledException') ? 'cancelled' : 'error';
                  result.error = String(error).slice(0, 8192);
                } else {
                  // Account for escaped Unicode as well as Base64 file expansion.
                  const size = jsonSize(value);
                  result.result = size > 393216 ? {captured: false, truncated: true, reason: 'Result exceeds 384 KiB'} : value;
                }
                result.finishedAt = Date.now();
                result.durationMs = Number(clock.elapsedRealtime()) - Number(start);
                active = null;
                current.resolve(result);
              }
              try {
                result.sender = identitySnapshot();
                send({noxenEvent: 'sender_started', jobId: current.jobId, startedAt: result.startedAt, sender: result.sender});
                const value = perform(current.request, current.signal, result);
                if (value && typeof value.then === 'function') value.then(v => finish(v), e => finish(null, e));
                else finish(value);
              } catch (error) { finish(null, error); }
            }},
          });
          job.signal = use('android.os.CancellationSignal').$new();
          use('java.lang.Thread').$new(workerClass.$new(), 'noxen-sender').start();
        } catch (error) { active = null; reject(error); }
      });
    });
  }
  function cancel(jobId) {
    return new Promise((resolve, reject) => J().perform(() => {
      try {
        if (!active || active.jobId !== jobId) { resolve(false); return; }
        if (!['query', 'openFileDescriptor'].includes(active.request.operation)) {
          throw new Error('This operation cannot be cancelled');
        }
        if (!active.signal) { resolve(false); return; }
        active.signal.cancel();
        resolve(true);
      } catch (error) { reject(error); }
    }));
  }
  return {identity, execute, cancel, checkActivityContext: () => J().performNow(activityContext)};
}
module.exports = {createSender};
