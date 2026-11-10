// Passive, bounded Monitor. Unknown objects are never stringified or traversed.
function createMonitor(Java, sendMessage, schedule) {
  const installed = new Map();
  let revision = -1, queue = [], dropped = 0, sequence = 0, inspecting = false;
  function safe(fn, fallback) { try { return fn(); } catch (_) { return fallback; } }
  function value(v, type) {
    if (v === null || v === undefined) return { type: type, value: null };
    if (type === 'java.lang.String' || type === 'char' || typeof v === 'string') {
      const s = String(v);
      return { type: type, value: s.slice(0, 2048), truncated: s.length > 2048 };
    }
    if (typeof v === 'boolean' || typeof v === 'number')
      return { type: type, value: typeof v === 'number' && !Number.isFinite(v) ? String(v) : v };
    return { type: type, opaque: true };
  }
  function inspect(fn) {
    inspecting = true;
    try { return safe(fn, { captureError: true }); } finally { inspecting = false; }
  }
  function emit(event) {
    if (queue.length >= 128) { dropped++; return; }
    queue.push(event);
  }
  schedule(function () {
    if (!queue.length && !dropped) return;
    const batch = queue.splice(0, 32), lost = dropped;
    dropped = 0;
    try { sendMessage({ noxenEvent: 'monitor_batch', events: batch, dropped: lost }); }
    catch (_) { dropped += batch.length + lost; }
  }, 100);
  function configure(hooks, nextRevision) {
    revision = nextRevision;
    Java.perform(function () {
      if (nextRevision !== revision) return;
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
              if (inspecting || !record.specs.length) return method.apply(this, arguments);
              if (queue.length >= 128) { dropped++; return method.apply(this, arguments); }
              const specs = record.specs.slice(), args = arguments;
              // Capture only while inspecting; original app calls stay observable.
              const event = { id: ++sequence, time: Date.now(), revision: revision,
                profiles: specs.map(s => s.profileName),
                class: specs[0].class, method: specs[0].method, types: specs[0].args,
                thread: safe(() => String(Process.getCurrentThreadId()), 'unknown') };
              if (specs.some(s => s.captureArguments))
                event.arguments = specs[0].args.map((t, i) => inspect(() => value(args[i], t)));
              if (specs.some(s => s.captureStack))
                event.stack = inspect(() => Java.backtrace({ limit: 16 }).frames.map(f => f.signature));
              let result;
              try { result = method.apply(this, arguments); }
              catch (error) {
                event.outcome = 'exception';
                event.exception = inspect(() => ({ type: error.$className || 'unknown', opaque: true }));
                emit(event);
                throw error;
              }
              event.outcome = 'returned';
              if (specs.some(s => s.captureReturn))
                event.result = inspect(() => value(result, method.returnType.className));
              emit(event);
              return result;
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
  return { configure: configure };
}
module.exports = { createMonitor };
