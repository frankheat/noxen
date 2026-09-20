import Java_bridge from 'frida-java-bridge';

// Frida >= 17 compatibility: Java bridge is no longer injected as a global.
// In Frida < 17 globalThis.Java is still set automatically; we reuse it to
// avoid double-loading. In >= 17 globalThis.Java is undefined, so we use the
// explicitly imported frida-java-bridge.
const Java = typeof globalThis.Java !== 'undefined' ? globalThis.Java : Java_bridge;
// Re-export as global so any script appended at runtime (e.g. via -l) can use it.
// On Frida < 17 Java is a read-only built-in, so we skip this silently.
try { globalThis.Java = Java; } catch (_) {}

var lock = null;
var ObjectJava = null;
var UriJava = null; 

// State
var blockEnabled = true;
var waiting = false;
var activeDecisionId = null;
var resumeMode = "forward"; 
var modQueue = []; 
var holdCounter = 0;
var decisionCounter = 0;

// --- Capture full stack trace ---
function getStackTrace() {
  var trace = [];
  var stack = Java.use("java.lang.Thread").currentThread().getStackTrace();
  for (var i = 2; i < stack.length; i++) {
    trace.push(stack[i].toString());
  }
  return trace;
}

function getProcessName() {
  try {
    var ActivityThread = Java.use("android.app.ActivityThread");
    var name = ActivityThread.currentProcessName();
    return name ? String(name) : "";
  } catch (e) {
    return "";
  }
}

function getPackageName() {
  try {
    var ActivityThread = Java.use("android.app.ActivityThread");
    var app = ActivityThread.currentApplication();
    if (app) return String(app.getPackageName());
  } catch (e) {}
  return "";
}

function beginHold(className, methodName) {
  holdCounter += 1;
  var holdId = "noxen-" + Process.id + "-" + holdCounter;
  send({
    "noxenEvent": "hold_start",
    "holdId": holdId,
    "pid": Process.id,
    "packageName": getPackageName(),
    "processName": getProcessName(),
    "className": className,
    "methodName": methodName
  });
  return holdId;
}

function endHold(holdId) {
  if (!holdId) return;
  send({
    "noxenEvent": "hold_end",
    "holdId": holdId,
    "pid": Process.id
  });
}

function dumpIntent(intent) {
  var infoIntent = {}
  if (intent === null) return infoIntent;

  try {
    var component = intent.getComponent();
    infoIntent.component = component ? (component.getPackageName() + "/" + component.getClassName()) : null;
    infoIntent.action = intent.getAction() || null    
    infoIntent.data = intent.getDataString() || null
    infoIntent.flags = intent.getFlags(); 

    var cats = intent.getCategories(); 
    var catList = [];
    if (cats !== null) {
        var iterator = cats.iterator();
        while (iterator.hasNext()) {
            catList.push(iterator.next().toString());
        }
    }
    infoIntent.categories = catList;

    var extrasObj = {};
    var extras = intent.getExtras();
    if (extras) {
      var iterator = extras.keySet().iterator();
      while (iterator.hasNext()) {
        var key = iterator.next();
        var value = extras.get(key);
        var type = value ? value.getClass().getName() : null;
        extrasObj[key] = { type: type, value: value ? value.toString() : null };
      }
    }
    infoIntent.extras = extrasObj
  } catch (e) {
    send("[!] Intent dump failed: " + e);
  }
  return infoIntent
}

function applyModifications(intent) {
  if (!intent || modQueue.length === 0) return;

  try {
    modQueue.forEach(function(mod) {
      if (mod.type === "action") {
        intent.setAction(mod.val);
      } 
      else if (mod.type === "data") {
        if (UriJava) intent.setData(UriJava.parse(mod.val));
      }
      else if (mod.type === "cat_add") {
        intent.addCategory(mod.val);
      }
      else if (mod.type === "cat_rem") {
        intent.removeCategory(mod.val);
      }
      else if (mod.type === "flag_add") {
        var f = intent.getFlags();
        intent.setFlags(f | parseInt(mod.val));
      }
      else if (mod.type === "flag_rem") {
        var f = intent.getFlags();
        intent.setFlags(f & ~parseInt(mod.val)); 
      }
      else if (mod.type === "extra_rem") {
        intent.removeExtra(mod.key);
      }
      else if (mod.type === "extra_add") {
        
        var key = mod.key;
        var val = mod.val;
        var eType = mod.extraType || "string";

        if (eType === "int") {
           intent.putExtra.overload("java.lang.String", "int").call(intent, key, parseInt(val));
        } 
        else if (eType === "bool" || eType === "boolean") {
           var bVal = (String(val).toLowerCase() === "true");
           intent.putExtra.overload("java.lang.String", "boolean").call(intent, key, bVal);
        }
        else if (eType === "long") {
           intent.putExtra.overload("java.lang.String", "long").call(intent, key, int64(val));
        }
        else if (eType === "float") {
           intent.putExtra.overload("java.lang.String", "float").call(intent, key, parseFloat(val));
        }
        else if (eType === "double") {
           intent.putExtra.overload("java.lang.String", "double").call(intent, key, parseFloat(val));
        }
        else {
           intent.putExtra.overload("java.lang.String", "java.lang.String").call(intent, key, String(val));
        }
      }
    });
  } catch (e) {
    send("[!] Error applying modifications: " + e);
  }
  modQueue = [];
}

// Methods where the CALLER receives intents — the exposed component is the caller.
var RECEIVING_METHODS = {
  "getIntent": true, "onNewIntent": true, "onActivityResult": true, "setResult": true,
  "onReceive": true, "onStartCommand": true, "onBind": true
};

// Sending methods — the exposed component is the intent's target. Maps to the
// PackageManager component type used to resolve/query that target.
var SENDING_TARGET_TYPE = {
  "startActivity": "activity", "startActivityForResult": "activity", "getActivity": "activity",
  "startService": "service", "startForegroundService": "service", "bindService": "service", "getService": "service",
  "sendBroadcast": "receiver", "sendOrderedBroadcast": "receiver", "getBroadcast": "receiver"
};

// PermissionInfo.protectionLevel base bits (& PROTECTION_MASK_BASE, 0xf); works on
// every API level, unlike getProtection() which is API 28+.
var PROTECTION_LEVELS = {
  0: "normal", 1: "dangerous", 2: "signature", 3: "signatureOrSystem", 4: "internal"
};

// {name, level} for a permission, or null. level is "unknown" when the permission
// is not declared by any installed/visible package.
function describePermission(pm, permName) {
  if (!permName) return null;
  var level = "unknown";
  try {
    level = PROTECTION_LEVELS[pm.getPermissionInfo(permName, 0).protectionLevel.value & 0xf] || "unknown";
  } catch (e) {}
  return { name: String(permName), level: level };
}

// Effective permission guarding a component: its own android:permission, falling
// back to the application-level android:permission when it declares none.
function effectiveComponentPermission(componentInfo) {
  try {
    var own = componentInfo.permission.value;
    if (own) return String(own);
  } catch (e) {}
  try {
    var appPerm = componentInfo.applicationInfo.value.permission.value;
    if (appPerm) return String(appPerm);
  } catch (e) {}
  return null;
}

function getPackageManagerSafe(context) {
  try {
    if (context && context.getPackageManager) return context.getPackageManager();
  } catch (e) {}
  try {
    var app = Java.use("android.app.ActivityThread").currentApplication();
    if (app) return app.getPackageManager();
  } catch (e) {}
  return null;
}

function componentInfoFor(pm, targetType, cn) {
  if (targetType === "service") return pm.getServiceInfo(cn, 0);
  if (targetType === "receiver") return pm.getReceiverInfo(cn, 0);
  return pm.getActivityInfo(cn, 0);
}

function fillTargetFromInfo(result, info, pm) {
  result.targetExported = info.exported.value;
  result.targetPermission = describePermission(pm, effectiveComponentPermission(info));
}

// Populate target fields on `result`: the resolved component, its exported flag and
// required permission, plus flags for implicit resolution / unreadable / multi-receiver.
function resolveSendTarget(pm, targetType, intent, result) {
  var cn = intent.getComponent();
  if (cn !== null) {
    result.targetComponent = cn.getPackageName() + "/" + cn.getClassName();
    try {
      fillTargetFromInfo(result, componentInfoFor(pm, targetType, cn), pm);
    } catch (e) {
      // Explicit target in another, non-visible app (Android 11+ package visibility).
      result.targetUnreadable = true;
    }
    return;
  }
  try {
    if (targetType === "activity") {
      var ria = pm.resolveActivity(intent, 0);
      if (ria !== null) fillTargetFromResolveInfo(result, ria, "activityInfo", pm);
    } else if (targetType === "service") {
      var ris = pm.resolveService(intent, 0);
      if (ris !== null) fillTargetFromResolveInfo(result, ris, "serviceInfo", pm);
    } else {
      var list = pm.queryBroadcastReceivers(intent, 0);
      if (list !== null && list.size() === 1) {
        fillTargetFromResolveInfo(result, list.get(0), "activityInfo", pm);
      } else if (list !== null && list.size() > 1) {
        result.targetReceiverCount = list.size();
      }
    }
  } catch (e) {}
}

function fillTargetFromResolveInfo(result, resolveInfo, infoField, pm) {
  var info = resolveInfo[infoField].value;
  result.targetComponent = info.packageName.value + "/" + info.name.value;
  result.targetResolved = true;
  fillTargetFromInfo(result, info, pm);
}

function buildAttackSurface(methodName, intent, self, firstArg, sendPermission) {
  var result = {};
  try {
    if (RECEIVING_METHODS[methodName]) {
      // onReceive: Context is the first argument; all other methods: 'this' is the Context
      var context = (methodName === "onReceive") ? firstArg : self;
      var pm = context.getPackageManager();
      var pkgName = context.getPackageName();
      // Use the runtime class name, not the hook class — e.g. MainActivity not Activity
      var runtimeClass = self.$className;
      var ComponentName = Java.use("android.content.ComponentName");
      var cn = ComponentName.$new(pkgName, runtimeClass);
      var info;
      if (methodName === "onReceive") {
        info = pm.getReceiverInfo(cn, 0);
      } else if (methodName === "onStartCommand" || methodName === "onBind") {
        info = pm.getServiceInfo(cn, 0);
      } else {
        info = pm.getActivityInfo(cn, 0);
      }
      result.callerExported = info.exported.value;
      result.callerPermission = describePermission(pm, effectiveComponentPermission(info));
    } else if (intent !== null) {
      result.intentExplicit = intent.getComponent() !== null;
      var targetType = SENDING_TARGET_TYPE[methodName];
      // 'this' is the Context for ContextWrapper sends; the Context is the first
      // argument for the static PendingIntent factories.
      var sendContext = (self && self.getPackageManager) ? self : firstArg;
      var sendPm = getPackageManagerSafe(sendContext);
      if (sendPm && targetType) {
        resolveSendTarget(sendPm, targetType, intent, result);
        if (sendPermission) result.broadcastPermission = describePermission(sendPm, sendPermission);
      }
    }
  } catch(e) {
    // Dynamic receiver, inner class, or component not in manifest — leave result empty
  }
  return result;
}

function processIntercept(className, methodName, intent, pendingIntentFlags, attackSurface) {
  var shouldDrop = false;
  var holdId = null;
  var decisionId = null;
  var isBlocking = false;

  try {
    var willBlock = blockEnabled && !waiting;
    if (willBlock) {
      waiting = true;
      isBlocking = true;
      decisionCounter += 1;
      decisionId = "decision-" + Process.id + "-" + decisionCounter;
      activeDecisionId = decisionId;
      resumeMode = "forward";
      modQueue = [];
    }

    var infoIntent = dumpIntent(intent);

    // --- SEND STACK TRACE ---
    send({
        "className": className,
        "methodName": methodName,
        "stackTrace": getStackTrace(),
        "infoIntent": infoIntent,
        "pendingIntentFlags": pendingIntentFlags !== undefined ? pendingIntentFlags : null,
        "attackSurface": attackSurface || null,
        "decision": {
          "required": willBlock,
          "id": decisionId,
          "reason": willBlock ? null : (blockEnabled ? "busy" : "intercept_off")
        }
    })
    
    if (!willBlock) return false;
    holdId = beginHold(className, methodName);

    Java.synchronized(lock, function () { lock.wait(); });

    var mode = resumeMode;
    
    if (mode === "drop") {
      shouldDrop = true;
    } else if (mode === "forward") {
      applyModifications(intent);
    }

    resumeMode = "forward";

  } catch (e) {
    send("[Blocking Error] " + e);
  } finally {
    if (isBlocking) {
      endHold(holdId);
      waiting = false;
      activeDecisionId = null;
    }
  }

  return shouldDrop;
}

function matchesActiveDecision(decisionId) {
  return waiting && (!decisionId || decisionId === activeDecisionId);
}

function returnTypeName(overload) {
  try {
    return overload.returnType.className || overload.returnType.name || "";
  } catch (_) {
    return "";
  }
}

function defaultReturn(returnType) {
  if (returnType === "void") return undefined;
  if (returnType === "boolean") return false;
  if (returnType === "char") return "\u0000";
  if (
    returnType === "byte" ||
    returnType === "double" ||
    returnType === "float" ||
    returnType === "int" ||
    returnType === "long" ||
    returnType === "short"
  ) {
    return 0;
  }
  return null;
}

function createHook(targetWrapper, className, methodName, overloadArgs) {
  const method = targetWrapper[methodName].overload.apply(targetWrapper[methodName], overloadArgs);
  const returnType = returnTypeName(method);
  const isPendingIntent = className === 'android.app.PendingIntent';

  // For sendBroadcast/sendOrderedBroadcast the first String parameter is the
  // receiverPermission the sender enforces on receivers. Locate its index once.
  let broadcastPermIndex = -1;
  if (methodName === "sendBroadcast" || methodName === "sendOrderedBroadcast") {
    broadcastPermIndex = overloadArgs.indexOf("java.lang.String");
  }

  method.implementation = function () {
    var firstArg = arguments.length > 0 ? arguments[0] : null;

    if (methodName === "getIntent") {
        var resultIntent = method.apply(this, arguments);
        var as = buildAttackSurface(methodName, resultIntent, this, null, null);
        var shouldDrop = processIntercept(this.$className, methodName, resultIntent, null, as);
        if (shouldDrop) return null;
        return resultIntent;
    }

    let intent = null;
    let pendingIntentFlags = null;

    if (isPendingIntent) {
      // getActivity/getBroadcast/getService: (Context, int requestCode, Intent, int flags[, Bundle])
      intent = arguments[2];
      pendingIntentFlags = arguments[3];
    } else {
      for (const arg of arguments) {
        if (arg && arg.$className === "android.content.Intent") {
          intent = arg;
          break;
        }
      }
    }

    var sendPermission = null;
    if (broadcastPermIndex >= 0 && arguments.length > broadcastPermIndex) {
      var permArg = arguments[broadcastPermIndex];
      if (permArg) sendPermission = String(permArg);
    }

    var as = buildAttackSurface(methodName, intent, this, firstArg, sendPermission);
    var shouldDrop = processIntercept(this.$className, methodName, intent, pendingIntentFlags, as);

    if (shouldDrop) return defaultReturn(returnType);

    try {
      return method.apply(this, arguments);
    } catch (e) {
      send("[!] Forward error in " + methodName + ": " + e);
      return defaultReturn(returnType);
    }
  };
}

rpc.exports = {
  proxy: function (hookConfig) {
    Java.perform(function () {
      send("[*] Initializing app hooks");
      ObjectJava = Java.use("java.lang.Object");
      UriJava = Java.use("android.net.Uri");

      if (lock === null) lock = ObjectJava.$new();

      var sdkInt = Java.use("android.os.Build$VERSION").SDK_INT.value;

      hookConfig.forEach(function(h) {
        if (h.minApi && sdkInt < h.minApi) {
          var sig = h.method + "(" + h.args.map(function(a) { return a.split('.').pop(); }).join(', ') + ")";
          send("[~] Skipping " + h.clazz + "." + sig + " (requires API " + h.minApi + ", device API " + sdkInt + ")");
          return;
        }
        try {
          var targetClass = Java.use(h.clazz);
          createHook(targetClass, h.clazz, h.method, h.args);
        } catch (e) {
          send("[!] Error registering hook " + h.clazz + ": " + e);
        }
      });
      send("[+] App hooks initialized");
    });
  },

  forward: function (decisionId) {
    var resumed = false;
    try {
      Java.performNow(function () {
        if (matchesActiveDecision(decisionId) && lock) {
          resumeMode = "forward";
          Java.synchronized(lock, function () { lock.notify(); });
          resumed = true;
        }
      });
    } catch (e) {
      send("[!] Forward resume failed: " + e);
    }
    return resumed;
  },

  drop: function (decisionId) {
    var resumed = false;
    try {
      Java.performNow(function () {
        if (matchesActiveDecision(decisionId) && lock) {
          resumeMode = "drop";
          Java.synchronized(lock, function () { lock.notify(); });
          resumed = true;
        }
      });
    } catch (e) {
      send("[!] Drop resume failed: " + e);
    }
    return resumed;
  },

  stageMod: function (type, key, val, extraType, decisionId) {
    if (matchesActiveDecision(decisionId)) {
        modQueue.push({type: type, key: key, val: val, extraType: extraType});
        send("[+] Modification staged: " + type + (extraType ? " (" + extraType + ")" : ""));
        return true;
    } else {
        send("[!] Error: No intent blocked to modify.");
        return false;
    }
  },

  interceptoff: function () {
    try {
      Java.performNow(function () {
        blockEnabled = false;
        if (waiting && lock) {
          resumeMode = "forward";
          Java.synchronized(lock, function () { lock.notify(); });
        }
      });
    } catch (e) {
      send("[!] Intercept off failed: " + e);
    }
  },

  intercepton: function () {
    blockEnabled = true;
  },

  getSdkInt: function () {
    var sdkInt = 0;
    Java.performNow(function () {
      sdkInt = Java.use("android.os.Build$VERSION").SDK_INT.value;
    });
    return sdkInt;
  },

  // Snapshot of the hooked app: identity, build flags, signing, permissions, components.
  // Read-only PackageManager queries on our own package (no package-visibility limits).
  getAppInfo: function () {
    var out = {};
    Java.performNow(function () {
      function s(v) { return (v === null || v === undefined) ? null : String(v); }
      function tryGet(fn) { try { return fn(); } catch (e) { return null; } }
      try {
        var ActivityThread = Java.use("android.app.ActivityThread");
        var ctx = ActivityThread.currentApplication();
        var pm = ctx.getPackageManager();
        var pkg = String(ctx.getPackageName());
        var sdkInt = Java.use("android.os.Build$VERSION").SDK_INT.value;

        var GET_ACTIVITIES = 1, GET_RECEIVERS = 2, GET_SERVICES = 4, GET_PROVIDERS = 8,
            GET_META_DATA = 128, GET_SIGNATURES = 64, GET_PERMISSIONS = 4096,
            GET_SIGNING_CERTIFICATES = 134217728;
        var flags = GET_ACTIVITIES | GET_RECEIVERS | GET_SERVICES | GET_PROVIDERS |
                    GET_META_DATA | GET_PERMISSIONS |
                    (sdkInt >= 28 ? GET_SIGNING_CERTIFICATES : GET_SIGNATURES);
        var pi = pm.getPackageInfo(pkg, flags);
        var ai = pi.applicationInfo.value;

        out.identity = {
          package: pkg,
          label: tryGet(function () { return String(pm.getApplicationLabel(ai)); }),
          versionName: tryGet(function () { return s(pi.versionName.value); }),
          versionCode: tryGet(function () { return sdkInt >= 28 ? String(pi.getLongVersionCode()) : String(pi.versionCode.value); }),
          uid: tryGet(function () { return ai.uid.value; }),
          pid: Process.id,
          processName: tryGet(function () { var n = ActivityThread.currentProcessName(); return n ? String(n) : null; }),
          sharedUserId: tryGet(function () { return s(pi.sharedUserId.value); }),
          installer: tryGet(function () {
            if (sdkInt >= 30) return s(pm.getInstallSourceInfo(pkg).getInstallingPackageName());
            return s(pm.getInstallerPackageName(pkg));
          }),
          firstInstallTime: tryGet(function () { return pi.firstInstallTime.value; }),
          lastUpdateTime: tryGet(function () { return pi.lastUpdateTime.value; })
        };

        var f = ai.flags.value;
        out.build = {
          deviceSdk: sdkInt,
          targetSdk: tryGet(function () { return ai.targetSdkVersion.value; }),
          minSdk: tryGet(function () { return ai.minSdkVersion.value; }),
          compileSdk: tryGet(function () { return ai.compileSdkVersion.value; }),
          debuggable: (f & 2) !== 0,
          allowBackup: (f & 32768) !== 0,
          testOnly: (f & 256) !== 0,
          extractNativeLibs: (f & 268435456) !== 0,
          cleartextPermitted: tryGet(function () { return Java.use("android.security.NetworkSecurityPolicy").getInstance().isCleartextTrafficPermitted(); }),
          nscPresent: tryGet(function () { return ai.networkSecurityConfigRes.value !== 0; })
        };

        out.signing = tryGet(function () {
          var MD = Java.use("java.security.MessageDigest");
          function sha256(bytes) {
            var md = MD.getInstance("SHA-256");
            var d = md.digest.overload("[B").call(md, bytes);
            var h = "";
            for (var i = 0; i < d.length; i++) { var b = d[i] & 0xff; h += (b < 16 ? "0" : "") + b.toString(16); }
            return h.toUpperCase();
          }
          var digs = [], multiple = false;
          if (sdkInt >= 28 && pi.signingInfo.value !== null) {
            var si = pi.signingInfo.value;
            var signers = si.getApkContentsSigners();
            for (var i = 0; i < signers.length; i++) digs.push(sha256(signers[i].toByteArray()));
            multiple = si.hasMultipleSigners();
          } else if (pi.signatures.value !== null) {
            var sigs = pi.signatures.value;
            for (var j = 0; j < sigs.length; j++) digs.push(sha256(sigs[j].toByteArray()));
          }
          return { sha256: digs, multipleSigners: multiple };
        }) || { sha256: [], multipleSigners: false };

        var perms = [];
        tryGet(function () {
          var req = pi.requestedPermissions.value, fl = pi.requestedPermissionsFlags.value;
          if (req !== null) {
            for (var i = 0; i < req.length; i++) {
              var nm = String(req[i]);
              var granted = fl !== null ? ((fl[i] & 2) !== 0) : null;
              var dp = describePermission(pm, nm);
              perms.push({ name: nm, source: "requested", granted: granted, level: dp ? dp.level : "unknown" });
            }
          }
        });
        tryGet(function () {
          var defs = pi.permissions.value;
          if (defs !== null) {
            for (var i = 0; i < defs.length; i++) {
              var p = defs[i];
              perms.push({ name: String(p.name.value), source: "defined", granted: null,
                           level: (PROTECTION_LEVELS[p.protectionLevel.value & 0xf] || "unknown") });
            }
          }
        });
        out.permissions = perms;

        var ComponentName = Java.use("android.content.ComponentName");
        function enumComponents(arr, type) {
          var res = [];
          if (arr === null) return res;
          for (var i = 0; i < arr.length; i++) {
            var ci = arr[i];
            var name = tryGet(function () { return String(ci.name.value); });
            var c = {
              name: name,
              type: type,
              exported: tryGet(function () { return ci.exported.value; }),
              permission: describePermission(pm, effectiveComponentPermission(ci)),
              enabled: tryGet(function () { return ci.enabled.value; }),
              enabledRuntime: tryGet(function () { return pm.getComponentEnabledSetting(ComponentName.$new(pkg, name)); }),
              processName: tryGet(function () { return s(ci.processName.value); }),
              directBootAware: tryGet(function () { return ci.directBootAware.value; })
            };
            if (type === "activity") {
              c.launchMode = tryGet(function () { return ci.launchMode.value; });
              c.taskAffinity = tryGet(function () { return s(ci.taskAffinity.value); });
              c.targetActivity = tryGet(function () { return s(ci.targetActivity.value); });
            } else if (type === "service") {
              c.foregroundServiceType = tryGet(function () { return ci.foregroundServiceType.value; });
            } else if (type === "provider") {
              c.authority = tryGet(function () { return s(ci.authority.value); });
              c.readPermission = tryGet(function () { return s(ci.readPermission.value); });
              c.writePermission = tryGet(function () { return s(ci.writePermission.value); });
              c.grantUriPermissions = tryGet(function () { return ci.grantUriPermissions.value; });
              c.multiprocess = tryGet(function () { return ci.multiprocess.value; });
            }
            res.push(c);
          }
          return res;
        }
        var comps = [];
        comps = comps.concat(enumComponents(pi.activities.value, "activity"));
        comps = comps.concat(enumComponents(pi.services.value, "service"));
        comps = comps.concat(enumComponents(pi.receivers.value, "receiver"));
        comps = comps.concat(enumComponents(pi.providers.value, "provider"));
        out.components = comps;
      } catch (e) {
        out.error = String(e);
      }
    });
    return out;
  }
};
