// Provider calls share the Intent hold slot. Cursor reads require an explicit decision.
const { snapshotCursor, previewCursor, validateTable, buildCursor } = require('./provider_cursor.js');
function createProviderInterceptor(Java, emit, options) {
  const send = event => { try { emit(event); return true; } catch (_) { return false; } };
  const RESOLVER = 'android.content.ContentResolver';
  const TRANSPORT = 'android.content.ContentProvider$Transport';
  const URI = 'android.net.Uri', STRING = 'java.lang.String', STRINGS = '[Ljava.lang.String;';
  const VALUES = 'android.content.ContentValues', BUNDLE = 'android.os.Bundle';
  const methods = new Set(['query', 'getType', 'insert', 'update', 'delete', 'call',
    'openFile', 'openAssetFile', 'openTypedAssetFile', 'openFileDescriptor',
    'openInputStream', 'openOutputStream', 'openTypedAssetFileDescriptor']);
  const installed = new Map(), depth = new Set(), dropped = new Set();
  let enabled = { outgoing: false, incoming: false }, pending = null, serial = 0, lock;
  let capturePreviews = false;
  const javaText = text => text === null ? null : text.includes('\u0000')
    ? Java.use(STRING).$new(Java.array('char', text.split(''))) : text;

  function descriptors(method, types, direction) {
    const fields = [], counts = {};
    const stringNames = {
      query: ['selection', 'sortOrder'], update: ['selection'], delete: ['selection'],
      call: direction === 'incoming' ? ['authority', 'method', 'arg'] : ['method', 'arg'],
      openFile: ['mode'], openAssetFile: ['mode'], openTypedAssetFile: ['mimeType'],
      openFileDescriptor: ['mode'], openOutputStream: ['mode'], openTypedAssetFileDescriptor: ['mimeType'],
    };
    types.forEach((type, index) => {
      counts[type] = (counts[type] || 0) + 1;
      let name;
      if (type === URI) name = 'uri';
      else if (type === STRING) {
        if (method === 'call' && types[0] === STRING && direction === 'outgoing')
          name = ['authority', 'method', 'arg'][counts[type] - 1];
        else name = (stringNames[method] || [])[counts[type] - 1];
      } else if (type === STRINGS) name = method === 'query' && counts[type] === 1 ? 'projection' : 'selectionArgs';
      else if (type === VALUES) name = 'values';
      else if (type === BUNDLE && ['query', 'update', 'delete'].includes(method)) name = 'queryArguments';
      if (name) fields.push({ name, index, type });
    });
    return fields;
  }

  function capture(args, fields) {
    const values = Object.create(null), editable = [];
    let queryArgumentsComplete = false;
    for (const field of fields) {
      const arg = args[field.index];
      let value = null;
      if (arg != null) {
        if (field.type === URI) {
          if (!['android.net.Uri$StringUri', 'android.net.Uri$HierarchicalUri', 'android.net.Uri$OpaqueUri'].includes(arg.$className))
            continue;
          value = String(arg.toString());
        } else if (field.type === VALUES) {
          const source = Java.cast(arg, Java.use(VALUES));
          if (source.size() > 32) continue;
          value = Object.create(null);
          const keys = source.keySet().iterator();
          let supported = true;
          while (keys.hasNext()) {
          const key = String(keys.next()), item = source.get(key);
            if (item === null) { value[key] = { type: 'String', value: null }; continue; }
            const kind = item.$className;
            if (kind === STRING) value[key] = { type: 'String', value: String(item) };
            else if (kind === 'java.lang.Integer') value[key] = { type: 'int', value: Java.cast(item, Java.use(kind)).intValue() };
            else if (kind === 'java.lang.Long') value[key] = { type: 'long', value: String(item) };
            else if (kind === 'java.lang.Boolean') value[key] = { type: 'boolean', value: Java.cast(item, Java.use(kind)).booleanValue() };
            else { supported = false; break; }
          }
          if (!supported) continue;
        } else if (field.type === BUNDLE) {
          // Do not unpack an incoming, still parcelled Bundle just to display it.
          const source = Java.cast(arg, Java.use(BUNDLE));
          if (source.isParcelled() !== false) continue;
          value = {};
          for (const [name, key] of [['selection', 'selection'], ['selectionArgs', 'selection-args'], ['sortOrder', 'sort-order']]) {
            const full = 'android:query-arg-sql-' + key;
            if (name === 'selectionArgs') {
              const array = source.getStringArray(full);
              if (array !== null && array.length > 64) { value = null; break; }
              value[name] = array === null ? null : Array.from(array, String);
            } else {
              const text = source.getString(full);
              value[name] = text === null ? null : String(text);
            }
          }
          if (value === null) continue;
          const allowed = {
            'android:query-arg-sql-selection': STRING,
            'android:query-arg-sql-selection-args': STRINGS,
            'android:query-arg-sql-sort-order': STRING,
          };
          const keys = source.keySet();
          queryArgumentsComplete = keys.size() <= 3;
          if (queryArgumentsComplete) {
            const iterator = keys.iterator();
            while (iterator.hasNext()) {
              const key = String(iterator.next());
              const item = source.get(key);
              if (!Object.prototype.hasOwnProperty.call(allowed, key) ||
                  (item !== null && item.$className !== allowed[key])) {
                queryArgumentsComplete = false;
                break;
              }
            }
          }
        } else if (field.type === STRINGS) {
          if (arg.length > 64) continue;
          value = Array.from(arg, x => x == null ? null : String(x));
        } else value = String(arg);
        if (JSON.stringify(value).length > 8192) continue;
      }
      values[field.name] = value;
      editable.push(field);
    }
    return { values, editable, queryArgumentsComplete };
  }

  function resultValue(result, type) {
    if (result == null || type === 'void') return { type, value: null };
    if (type === 'boolean' || type === 'int') return { type, value: result };
    if (type === STRING) return { type, value: String(result).slice(0, 2048) };
    if (type === URI && ['android.net.Uri$StringUri', 'android.net.Uri$HierarchicalUri',
                        'android.net.Uri$OpaqueUri'].includes(result.$className)) {
      try {
        const value = options.inspect(() => String(result.toString()));
        if (value.length <= 8192) return { type, value };
        return { type, opaque: true, reason: 'URI exceeds capture limit' };
      } catch (error) {
        return { type, opaque: true, reason: 'URI could not be read' };
      }
    }
    return { type: result.$className || type, opaque: true };
  }

  function invoke(record, self, args) {
    const thread = Process.getCurrentThreadId();
    if (!enabled[record.direction] || depth.has(thread)) return record.method.apply(self, args);
    const previewEnabled = capturePreviews;
    depth.add(thread);
    let owned = false, hold = null, interrupted = false, id;
    try {
      let captured;
      try { captured = options.inspect(() => capture(args, record.fields)); }
      catch (_) { captured = { values: {}, editable: [] }; }
      id = 'provider-' + Process.id + '-' + (++serial);
      const uri = captured.values.uri || '';
      const authority = (captured.values.authority || /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(uri)?.[1] || '')
        .replace(/^\d+@/, '');
      const filterMatch = options.filter ? options.filter({
        event: 'provider', direction: record.direction, class: record.className, method: record.name,
        data: uri, uri, authority, flags: '', category: [],
      }) : null;
      owned = filterMatch !== false && options.claim();
      const event = { noxenEvent: 'provider_request', ...options.stamp(), id,
        direction: record.direction, class: record.className, method: record.name,
        types: record.types, arguments: captured.values,
        queryArgumentsComplete: captured.queryArgumentsComplete === true,
        nullArguments: record.types.map((_, index) => index).filter(index => args[index] == null),
        opaqueArguments: record.types.map((type, i) => ({ index: i, type }))
          .filter(x => !captured.editable.some(f => f.index === x.index)),
        state: owned ? 'held' : 'forwarded', phase: 'request', decisionId: owned ? id : null,
        filterChecked: filterMatch !== null };
      if (!owned) event.decision = filterMatch === false || (options.blocking && !options.blocking())
        ? 'forwarded' : 'forwarded_busy';
      if (record.direction === 'incoming')
        event.callingUid = Java.use('android.os.Binder').getCallingUid();
      if (owned) pending = { id, event, args: Array.from(args), fields: captured.editable, mode: null };
      if (!send(event)) return record.method.apply(self, args);
      let callArgs = args, skipResponse = false;
      if (owned) {
        hold = options.begin(record.className, record.name);
        while (true) {
          Java.synchronized(lock, () => {
            while (pending.mode === null) {
              try { lock.wait(); }
              catch (error) {
                if (!error.$h || !Java.use('java.lang.InterruptedException').class.isInstance(error))
                  throw error;
                interrupted = true;
              }
            }
          });
          if (pending.mode === 'drop') break;
          try {
            callArgs = options.inspect(() => buildArguments(pending));
            break;
          } catch (error) {
            pending.mode = null;
            send({ noxenEvent: 'provider_edit_error', id, state: 'held', error: String(error).slice(0, 512) });
          }
        }
        const decision = pending;
        pending = null;
        skipResponse = decision.skipResponse;
        if (decision.mode === 'drop') {
          send({ noxenEvent: 'provider_result', id, state: 'dropped', ...options.stamp(), releasedAt: Date.now() });
          throw Java.use('android.os.OperationCanceledException').$new('Blocked by noxen');
        }
        send({ noxenEvent: 'provider_update', id, state: decision.edited ? 'modified_forwarded' : 'forwarded',
          sentArguments: decision.values || event.arguments, error: null, releasedAt: Date.now() });
      }
      if (interrupted) {
        Java.use('java.lang.Thread').currentThread().interrupt();
        interrupted = false;
      }
      try {
        let result = record.method.apply(self, callArgs);
        const isCursor = record.method.returnType.className === 'android.database.Cursor' && result != null;
        const isMime = record.name === 'getType' && record.method.returnType.className === STRING;
        const originalResult = resultValue(result, record.method.returnType.className);
        let preview = {};
        if (owned && !skipResponse && (!options.blocking || options.blocking()) && (isCursor || isMime)) {
          result = response(id, result, event, isMime, previewEnabled);
        } else if (previewEnabled && isCursor) {
          try {
            preview = { cursorPreview: options.inspect(() => previewCursor(result)) };
          } catch (error) {
            preview = { cursorPreviewError: String(error).slice(0, 512) };
          }
        }
        send({ noxenEvent: 'provider_result', id, state: 'returned', ...options.stamp(),
          result: originalResult, decisionId: null, ...preview });
        return result;
      } catch (error) {
        if (!dropped.has(id)) send({ noxenEvent: 'provider_result', id, state: 'exception', ...options.stamp(),
          exception: String(error).slice(0, 2048) });
        throw error;
      }
    } finally {
      depth.delete(thread);
      dropped.delete(id);
      if (owned) {
        pending = null;
        options.release();
        if (hold !== null) options.end(hold);
      }
      if (interrupted) Java.use('java.lang.Thread').currentThread().interrupt();
    }
  }

  function response(id, original, request, isMime = false, automaticPreview = false) {
    const decisionId = id + ':response';
    const event = { noxenEvent: 'provider_response', id, state: 'held', phase: 'response',
      decisionId, result: resultValue(original, isMime ? STRING : 'android.database.Cursor'), ...options.stamp(),
      ...(isMime ? { editableResult: { value: original === null ? null : String(original) } } : {}) };
    pending = { id: decisionId, event, mode: null, values: null, snapshot: null, isMime };
    if (automaticPreview && !isMime) {
      try {
        const preview = options.inspect(() => previewCursor(original));
        if (preview.complete) {
          const table = { columns: preview.columns, rows: preview.rows };
          try {
            validateTable(table);
            pending.snapshot = table;
            event.cursor = table;
          } catch (error) {
            event.cursorPreview = preview;
            event.error = String(error).slice(0, 512);
          }
        } else {
          event.cursorPreview = preview;
        }
      } catch (error) {
        event.cursorPreviewError = String(error).slice(0, 512);
      }
    }
    if (!send(event)) { pending = null; return original; }
    let interrupted = false;
    try {
      while (true) {
        Java.synchronized(lock, () => {
          while (pending.mode === null) {
            try { lock.wait(); }
            catch (error) {
              if (!error.$h || !Java.use('java.lang.InterruptedException').class.isInstance(error)) throw error;
              interrupted = true;
            }
          }
        });
        const decision = pending;
        if (decision.mode === 'inspect') {
          decision.mode = null;
          try {
            decision.snapshot = options.inspect(() => snapshotCursor(original));
            send({ noxenEvent: 'provider_response', id, state: 'held', phase: 'response',
              decisionId, cursor: decision.snapshot, error: null });
          } catch (error) {
            decision.snapshot = null;
            send({ noxenEvent: 'provider_edit_error', id, state: 'held', phase: 'response',
              decisionId, error: String(error).slice(0, 512) });
          }
          continue;
        }
        if (decision.mode === 'drop') {
          dropped.add(id);
          try { original.close(); } catch (_) {}
          send({ noxenEvent: 'provider_result', id, state: 'dropped', decisionId: null, ...options.stamp(), releasedAt: Date.now() });
          throw Java.use('android.os.OperationCanceledException').$new('Blocked by noxen');
        }
        let result = original;
        try {
          if (decision.values !== null) {
            if (isMime) {
              if (decision.values.value !== (original === null ? null : String(original)))
                result = options.inspect(() => javaText(decision.values.value));
            } else if (JSON.stringify(decision.values) !== JSON.stringify(decision.snapshot)) {
              result = options.inspect(() => buildCursor(Java, decision.values, javaText));
            }
          }
        } catch (error) {
          decision.mode = null;
          send({ noxenEvent: 'provider_edit_error', id, state: 'held', phase: 'response',
            decisionId, error: String(error).slice(0, 512) });
          continue;
        }
        if (result !== original) {
          try { original.close(); } catch (_) { /* Replacement owns its own resources. */ }
        }
        send({ noxenEvent: 'provider_update', id, state: result === original ? 'forwarded' : 'modified_forwarded',
          phase: 'response', decisionId: null,
          ...(result === original ? {} : isMime
            ? { sentResult: { type: STRING, value: decision.values.value } }
            : { sentCursor: decision.values }),
          releasedAt: Date.now(), error: null });
        return result;
      }
    } finally {
      pending = null;
      if (interrupted) Java.use('java.lang.Thread').currentThread().interrupt();
    }
  }

  function buildArguments(decision) {
    const args = decision.args.slice(), values = decision.values;
    if (values == null) return args;
        for (const field of decision.fields) {
          const value = values[field.name];
          if (field.type === VALUES) {
            if (value !== null && (typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length > 32))
              throw new Error('values: expected a typed ContentValues object');
          } else if (field.type === BUNDLE) {
            if (value !== null && (typeof value !== 'object' || Array.isArray(value) ||
                JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(['selection', 'selectionArgs', 'sortOrder'])))
              throw new Error('queryArguments: keep selection, selectionArgs and sortOrder');
          } else if (field.type === STRINGS) {
            if (value !== null && (!Array.isArray(value) || value.length > 64 ||
                value.some(x => x !== null && typeof x !== 'string')))
              throw new Error(field.name + ': expected null or string array');
          } else if (value !== null && typeof value !== 'string')
            throw new Error(field.name + ': expected null or string');
          if (field.name === 'uri' && (value === null || !value.startsWith('content://')))
            throw new Error('uri: expected content:// URI');
          if (JSON.stringify(value).length > 8192) throw new Error(field.name + ': value too large');
          if (JSON.stringify(value) === JSON.stringify(decision.event.arguments[field.name])) continue;
          if (value === null) args[field.index] = null;
          else if (field.type === VALUES) {
            const target = Java.use(VALUES).$new();
            for (const [key, item] of Object.entries(value)) {
              if (!item || !['String', 'int', 'long', 'boolean'].includes(item.type))
                throw new Error('values: supported types are String, int, long and boolean');
              if (item.value === null) { target.putNull(key); continue; }
              const expected = { String: 'string', int: 'number', long: 'string', boolean: 'boolean' }[item.type];
              if (typeof item.value !== expected) throw new Error(key + ': invalid typed value');
              if (item.type === 'int' && (!Number.isInteger(item.value) || item.value < -2147483648 || item.value > 2147483647))
                throw new Error(key + ': integer out of range');
              const klass = 'java.lang.' + ({ int: 'Integer', long: 'Long', boolean: 'Boolean' }[item.type] || 'String');
              const boxed = item.type === 'String' ? javaText(item.value) : Java.use(klass).valueOf(String(item.value));
              target.put.overload(STRING, klass).call(target, javaText(key), boxed);
            }
            args[field.index] = target;
          } else if (field.type === BUNDLE) {
            const target = args[field.index] === null ? Java.use(BUNDLE).$new() : Java.use(BUNDLE).$new(args[field.index]);
            for (const [name, key] of [['selection', 'selection'], ['selectionArgs', 'selection-args'], ['sortOrder', 'sort-order']]) {
              const item = value[name], full = 'android:query-arg-sql-' + key;
              if (name === 'selectionArgs') {
                if (item !== null && (!Array.isArray(item) || item.length > 64 || item.some(x => typeof x !== 'string')))
                  throw new Error(name + ': expected null or string array');
                target.putStringArray(full, item === null ? null : Java.array(STRING, item.map(javaText)));
              } else {
                if (item !== null && typeof item !== 'string') throw new Error(name + ': expected null or string');
                target.putString(full, javaText(item));
              }
            }
            args[field.index] = target;
          } else args[field.index] = field.type === URI ? Java.use(URI).parse(javaText(value))
            : field.type === STRINGS ? Java.array(STRING, value.map(javaText)) : javaText(value);
        }

    return args;
  }

  function validateValues(values, fields) {
    if (!values || typeof values !== 'object' || Array.isArray(values)) throw new Error('Expected argument object');
    if (JSON.stringify(Object.keys(values).sort()) !== JSON.stringify(fields.map(f => f.name).sort()))
      throw new Error('Keep the captured argument keys; null clears a value');
    for (const field of fields) {
      const value = values[field.name];
      if (JSON.stringify(value).length > 8192) throw new Error(field.name + ': value too large');
      if (field.type === VALUES || field.type === BUNDLE) {
        if (value !== null && (typeof value !== 'object' || Array.isArray(value)))
          throw new Error(field.name + ': expected object or null');
      } else if (field.type === STRINGS) {
        if (value !== null && (!Array.isArray(value) || value.length > 64 ||
            value.some(x => x !== null && typeof x !== 'string')))
          throw new Error(field.name + ': expected null or string array');
      } else if (value !== null && typeof value !== 'string')
        throw new Error(field.name + ': expected null or string');
      if (field.name === 'uri' && (value === null || !value.startsWith('content://')))
        throw new Error('uri: expected content:// URI');
    }
  }

  function resolve(id, action, values, skipResponse = false) {
    let accepted = false;
    Java.performNow(() => Java.synchronized(lock, () => {
      if (!pending || pending.id !== id || pending.mode !== null) return;
      if (!['forward', 'drop', 'inspect'].includes(action)) throw new Error('Unknown provider decision');
      if (action === 'inspect' && (pending.event.phase !== 'response' || pending.snapshot !== null || pending.isMime))
        throw new Error('Cursor can only be read once while its response is held');
      pending.values = null;
      pending.edited = false;
      if (values != null && action === 'forward') {
        if (pending.event.phase === 'response') {
          if (pending.isMime) {
            if (typeof values !== 'object' || Array.isArray(values) || Object.keys(values).join(',') !== 'value' ||
                (values.value !== null && typeof values.value !== 'string') ||
                (typeof values.value === 'string' && values.value.length > 8192))
              throw new Error('Response requires value: a string up to 8192 characters or null');
          } else {
            if (pending.snapshot === null) throw new Error('Read Cursor before editing its response');
            validateTable(values);
          }
        } else validateValues(values, pending.fields);
        pending.edited = JSON.stringify(values) !== JSON.stringify(pending.event.arguments);
        pending.values = values;
      }
      pending.skipResponse = skipResponse;
      pending.mode = action;
      accepted = true;
      lock.notifyAll();
    }));
    return accepted;
  }

  function configure(outgoing, incoming, previews = false) {
    return new Promise((resolveConfig, reject) => Java.perform(() => {
      try {
        if (lock === undefined) lock = Java.use('java.lang.Object').$new();
        if (pending && !outgoing && !incoming) resolve(pending.id, 'forward', null);
        enabled = { outgoing: !!outgoing, incoming: !!incoming };
        capturePreviews = previews === true;
        const report = [];
        for (const [direction, className] of [['outgoing', RESOLVER], ['incoming', TRANSPORT]]) {
          if (!enabled[direction]) continue;
          let klass;
          try { klass = Java.use(className); }
          catch (error) {
            enabled[direction] = false;
            report.push({ direction, method: '*', types: [], state: 'Unavailable', error: String(error) });
            continue;
          }
          for (const name of methods) {
            if (!klass[name]) continue;
            for (const method of klass[name].overloads) {
              const key = String(method.handle);
              if (installed.has(key)) {
                report.push({ direction, method: name,
                  types: installed.get(key).types, state: 'Active' });
                continue;
              }
              const types = method.argumentTypes.map(t => t.className);
              if (direction === 'incoming' && types[0] !== 'android.content.AttributionSource') continue;
              // A call needs a URI or authority. Never expose AttributionSource/caller identity for editing.
              if (!types.includes(URI) && name !== 'call') continue;
              if (method.implementation !== null) {
                report.push({ direction, method: name, types, state: 'Conflict' });
                continue;
              }
              const record = { method, name, className, direction, types,
                fields: descriptors(name, types, direction) };
              method.implementation = function () { return invoke(record, this, arguments); };
              installed.set(key, record);
              report.push({ direction, method: name, types, state: 'Active' });
            }
          }
          if (!report.some(item => item.direction === direction && item.state === 'Active')) {
            enabled[direction] = false;
            if (!report.some(item => item.direction === direction))
              report.push({ direction, method: '*', types: [], state: 'Unavailable',
                error: 'No supported overloads on this Android version' });
          }
        }
        resolveConfig({ enabled, hooks: report });
      } catch (error) { enabled = { outgoing: false, incoming: false }; reject(error); }
    }));
  }
  function release() { if (pending) resolve(pending.id, 'forward', null); }
  function setCursorPreviews(enabled) {
    capturePreviews = enabled === true;
  }
  return { configure, resolve, release, setCursorPreviews };
}
module.exports = { createProviderInterceptor };
