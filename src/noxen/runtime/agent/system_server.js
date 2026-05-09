import Java_bridge from 'frida-java-bridge';

const Java = typeof globalThis.Java !== 'undefined' ? globalThis.Java : Java_bridge;
try { globalThis.Java = Java; } catch (_) {}

var config = { maxHoldMs: 120000 };
var hooksInstalled = false;
var hookStats = [];
var activeHolds = {};

function log(level, message) {
  send({
    "noxenEvent": "system_server_log",
    "level": level,
    "message": message
  });
}

function nowMs() {
  return Date.now();
}

function toInt(value) {
  if (value === null || value === undefined) return null;
  var parsed = parseInt(value);
  return isNaN(parsed) ? null : parsed;
}

function readField(obj, name) {
  try {
    if (obj && obj[name] !== undefined) {
      var field = obj[name];
      return field && field.value !== undefined ? field.value : field;
    }
  } catch (_) {}
  return null;
}

function callNoArgs(obj, name) {
  try {
    if (obj && obj[name]) return obj[name].call(obj);
  } catch (_) {}
  return null;
}

function pidFromProcessLike(obj) {
  if (!obj) return null;
  var pid = toInt(callNoArgs(obj, "getPid"));
  if (pid !== null) return pid;
  pid = toInt(readField(obj, "mPid"));
  if (pid !== null) return pid;
  pid = toInt(readField(obj, "pid"));
  if (pid !== null) return pid;
  return pidFromProcessLike(readField(obj, "mOwner"));
}

function pidFromWindowState(windowState) {
  if (!windowState) return null;
  var pid = toInt(readField(windowState, "mOwnerPid"));
  if (pid !== null) return pid;
  pid = toInt(readField(windowState, "ownerPid"));
  if (pid !== null) return pid;
  return pidFromProcessLike(readField(windowState, "mSession"));
}

function pidFromOptionalInt(optionalInt) {
  try {
    if (optionalInt && optionalInt.isPresent && optionalInt.isPresent()) {
      return toInt(optionalInt.getAsInt());
    }
  } catch (_) {}
  return null;
}

function serviceFrom(receiver) {
  return readField(receiver, "mService") ||
         readField(receiver, "mAtmService") ||
         readField(receiver, "mActivityTaskManager");
}

function pidFromToken(service, token) {
  if (!service || !token) return null;

  try {
    var inputTarget = service.getInputTargetFromToken(token);
    var pid = toInt(callNoArgs(inputTarget, "getPid"));
    if (pid !== null) return pid;
    pid = pidFromWindowState(callNoArgs(inputTarget, "getWindowState"));
    if (pid !== null) return pid;
  } catch (_) {}

  try {
    var inputMap = readField(service, "mInputToWindowMap");
    var windowState = inputMap ? inputMap.get(token) : null;
    var mappedPid = pidFromWindowState(windowState);
    if (mappedPid !== null) return mappedPid;
  } catch (_) {}

  try {
    var clientWindow = service.windowForClientLocked(null, token, false);
    var clientPid = pidFromWindowState(clientWindow);
    if (clientPid !== null) return clientPid;
  } catch (_) {}

  try {
    var embeddedController = readField(service, "mEmbeddedWindowController");
    var embedded = embeddedController ? embeddedController.get(token) : null;
    var embeddedPid = toInt(readField(embedded, "mOwnerPid"));
    if (embeddedPid !== null) return embeddedPid;
  } catch (_) {}

  return null;
}

function cleanupExpiredHolds() {
  var now = nowMs();
  Object.keys(activeHolds).forEach(function(pid) {
    if (activeHolds[pid].expiresAt <= now) delete activeHolds[pid];
  });
}

function holdForPid(pid) {
  cleanupExpiredHolds();
  var parsed = toInt(pid);
  if (parsed === null || parsed < 0) return null;
  return activeHolds[String(parsed)] || null;
}

function labelMatchesHold(label, hold) {
  if (!label || !hold) return false;
  var text = String(label);
  return (!!hold.packageName && text.indexOf(String(hold.packageName)) !== -1) ||
         (!!hold.processName && text.indexOf(String(hold.processName)) !== -1);
}

function holdForLabel(label) {
  cleanupExpiredHolds();
  var keys = Object.keys(activeHolds);
  for (var i = 0; i < keys.length; i++) {
    var hold = activeHolds[keys[i]];
    if (labelMatchesHold(label, hold)) return hold;
  }
  return null;
}

function holdForArgs(receiver, args) {
  var service = serviceFrom(receiver);

  for (var i = 0; i < args.length; i++) {
    var arg = args[i];

    var pid = typeof arg === "number" ? toInt(arg) : null;
    if (pid !== null) {
      var byNumber = holdForPid(pid);
      if (byNumber) return byNumber;
    }

    var byOptional = pidFromOptionalInt(arg);
    if (byOptional !== null) {
      var optionalHold = holdForPid(byOptional);
      if (optionalHold) return optionalHold;
    }

    var processPid = pidFromProcessLike(arg);
    if (processPid !== null) {
      var processHold = holdForPid(processPid);
      if (processHold) return processHold;
    }

    var tokenPid = pidFromToken(service, arg);
    if (tokenPid !== null) {
      var tokenHold = holdForPid(tokenPid);
      if (tokenHold) return tokenHold;
    }

    var name = readField(arg, "name") || readField(arg, "stringName") ||
               readField(arg, "shortComponentName") || callNoArgs(arg, "getName");
    var labelHold = holdForLabel(name);
    if (labelHold) return labelHold;
  }

  return null;
}

function remainingMs(hold) {
  return Math.max(1, hold.expiresAt - nowMs());
}

function remainingNanos(hold) {
  return remainingMs(hold) * 1000000;
}

function defaultReturn(returnType) {
  if (returnType === "void") return undefined;
  if (returnType === "boolean") return false;
  if (returnType === "long" || returnType === "int") return 0;
  return null;
}

function returnTypeName(overload) {
  try {
    return overload.returnType.className || overload.returnType.name || "";
  } catch (_) {
    return "";
  }
}

function describeHold(hold) {
  return "pid=" + hold.pid + " method=" + hold.methodName + " hold=" + hold.holdId;
}

function isMissingHookError(error) {
  var text = String(error || "");
  return text.indexOf("ClassNotFoundException") !== -1 ||
         text.indexOf("NoClassDefFoundError") !== -1 ||
         text.indexOf("TypeError: cannot read property") !== -1 ||
         text.indexOf("undefined is not an object") !== -1;
}

function shortHookError(error) {
  var text = String(error || "failed");
  if (text.indexOf("ClassNotFoundException") !== -1) return "class not available on this Android version";
  if (text.indexOf("NoClassDefFoundError") !== -1) return "class dependency not available on this Android version";
  var newline = text.indexOf("\n");
  if (newline !== -1) text = text.slice(0, newline);
  return text.length > 180 ? text.slice(0, 177) + "..." : text;
}

function installHook(className, methodName, handler) {
  var installed = 0;
  var status = "missing";
  var error = "";
  try {
    var Klass = Java.use(className);
    if (!Klass[methodName]) {
      hookStats.push({ className: className, methodName: methodName, installed: 0, status: status });
      return 0;
    }
    Klass[methodName].overloads.forEach(function(overload) {
      var returnType = returnTypeName(overload);
      overload.implementation = function() {
        return handler.call(this, overload, returnType, arguments);
      };
      installed += 1;
    });
    status = installed > 0 ? "installed" : "missing";
    if (installed > 0) {
      log("success", "Hooked " + className + "." + methodName + " (" + installed + " overloads)");
    }
  } catch (e) {
    error = shortHookError(e);
    if (isMissingHookError(e)) {
      status = "missing";
    } else {
      status = "error";
      log("warning", "Failed " + className + "." + methodName + ": " + error);
    }
  }
  hookStats.push({
    className: className,
    methodName: methodName,
    installed: installed,
    status: status,
    error: error
  });
  return installed;
}

function installHooks() {
  if (hooksInstalled) return;
  hooksInstalled = true;
  hookStats = [];

  var count = 0;

  count += installHook("com.android.server.wm.WindowProcessController", "getInputDispatchingTimeoutMillis",
    function(original, _returnType, args) {
      var hold = holdForPid(pidFromProcessLike(this));
      if (hold) {
        log("debug", "Extended dispatch timeout for " + describeHold(hold));
        return remainingMs(hold);
      }
      return original.apply(this, args);
    });

  count += installHook("com.android.server.wm.InputManagerCallback", "notifyANR",
    function(original, _returnType, args) {
      var hold = holdForArgs(this, args);
      if (hold) {
        log("debug", "Extended legacy input ANR for " + describeHold(hold));
        return remainingNanos(hold);
      }
      return original.apply(this, args);
    });

  count += installHook("com.android.server.wm.AnrController", "notifyWindowUnresponsive",
    function(original, returnType, args) {
      var hold = holdForArgs(this, args);
      if (hold) {
        log("debug", "Suppressed window ANR for " + describeHold(hold));
        return defaultReturn(returnType);
      }
      return original.apply(this, args);
    });

  count += installHook("com.android.server.wm.AnrController", "notifyAppUnresponsive",
    function(original, returnType, args) {
      var hold = holdForArgs(this, args);
      if (hold) {
        log("debug", "Suppressed app ANR for " + describeHold(hold));
        return defaultReturn(returnType);
      }
      return original.apply(this, args);
    });

  count += installHook("com.android.server.wm.AnrController", "notifyGestureMonitorUnresponsive",
    function(original, returnType, args) {
      var hold = holdForArgs(this, args);
      if (hold) {
        log("debug", "Suppressed gesture monitor ANR for " + describeHold(hold));
        return defaultReturn(returnType);
      }
      return original.apply(this, args);
    });

  count += installHook("com.android.server.wm.ActivityRecord", "inputDispatchingTimedOut",
    function(original, returnType, args) {
      var hold = holdForArgs(this, args) || holdForPid(pidFromProcessLike(readField(this, "app")));
      if (hold) {
        log("debug", "Declined ActivityRecord input ANR for " + describeHold(hold));
        return defaultReturn(returnType);
      }
      return original.apply(this, args);
    });

  count += installHook("com.android.server.am.ActivityManagerService", "inputDispatchingTimedOut",
    function(original, returnType, args) {
      var hold = holdForArgs(this, args);
      if (hold) {
        log("debug", "Declined ActivityManager input ANR for " + describeHold(hold));
        if (returnType === "long" || returnType === "int") return remainingMs(hold);
        return defaultReturn(returnType);
      }
      return original.apply(this, args);
    });

  if (count > 0) {
    log("success", "Input ANR bypass ready (" + count + " hook overloads)");
  } else {
    log("warning", "Input ANR bypass loaded, but no supported hook was installed");
  }
}

function capabilitySummary() {
  var installed = 0;
  var missing = 0;
  var errors = 0;
  hookStats.forEach(function(item) {
    if (item.installed > 0) installed += item.installed;
    else if (item.status === "error") errors += 1;
    else missing += 1;
  });
  return {
    installedOverloads: installed,
    missingHooks: missing,
    failedHooks: errors,
    hooks: hookStats
  };
}

rpc.exports = {
  init: function(newConfig) {
    if (newConfig && newConfig.maxHoldMs) {
      config.maxHoldMs = Math.max(1000, parseInt(newConfig.maxHoldMs));
    }
    Java.perform(function() {
      installHooks();
    });
  },

  holdstart: function(hold) {
    if (!hold || hold.pid === undefined || hold.pid === null) return;
    var pid = String(hold.pid);
    var maxHoldMs = Math.max(1000, toInt(hold.timeoutMs) || config.maxHoldMs);
    activeHolds[pid] = {
      holdId: String(hold.holdId || pid),
      pid: toInt(hold.pid),
      packageName: hold.packageName || "",
      processName: hold.processName || "",
      className: hold.className || "",
      methodName: hold.methodName || "",
      expiresAt: nowMs() + maxHoldMs
    };
  },

  holdend: function(holdId, pid) {
    var pidKey = pid !== undefined && pid !== null ? String(pid) : null;
    if (pidKey && activeHolds[pidKey]) {
      delete activeHolds[pidKey];
      return;
    }

    Object.keys(activeHolds).forEach(function(key) {
      if (activeHolds[key].holdId === String(holdId)) delete activeHolds[key];
    });
  },

  clear: function() {
    activeHolds = {};
  },

  status: function() {
    cleanupExpiredHolds();
    var caps = capabilitySummary();
    return {
      activeHolds: Object.keys(activeHolds).length,
      maxHoldMs: config.maxHoldMs,
      hooksInstalled: hooksInstalled,
      installedOverloads: caps.installedOverloads,
      missingHooks: caps.missingHooks,
      failedHooks: caps.failedHooks,
      hooks: caps.hooks
    };
  }
};
