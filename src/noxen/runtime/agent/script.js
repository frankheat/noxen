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

function normalizeExtraType(extraType) {
  var value = String(extraType || "string").toLowerCase();
  if (value.indexOf("--") === 0) value = value.slice(2);
  var aliases = {
    "boolean": "bool", "integer": "int", "integer[]": "int[]",
    "integer-list": "int-list", "null-string": "null", "string-null": "null",
    "component-name": "component",
    "es": "string", "esn": "null", "ez": "bool", "ei": "int",
    "el": "long", "ef": "float", "ed": "double", "eu": "uri",
    "ecn": "component", "eia": "int[]", "ela": "long[]",
    "efa": "float[]", "eda": "double[]", "esa": "string[]",
    "eial": "int-list", "elal": "long-list", "efal": "float-list",
    "edal": "double-list", "esal": "string-list"
  };
  return aliases[value] || value;
}

function splitExtraValues(value) {
  var result = [];
  var current = "";
  var escaped = false;
  var text = String(value);
  for (var i = 0; i < text.length; i++) {
    var ch = text[i];
    if (escaped) {
      if (ch !== "," && ch !== "\\") current += "\\";
      current += ch;
      escaped = false;
    } else if (ch === "\\") {
      escaped = true;
    } else if (ch === ",") {
      result.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  if (escaped) current += "\\";
  result.push(current);
  return result;
}

function escapeExtraString(value) {
  return String(value).replace(/\\/g, "\\\\").replace(/,/g, "\\,");
}

function parseAndroidInt(value) {
  var text = String(value).trim();
  var sign = 1;
  if (text[0] === "+" || text[0] === "-") {
    if (text[0] === "-") sign = -1;
    text = text.slice(1);
  }
  var radix = 10;
  if (text.indexOf("0x") === 0 || text.indexOf("0X") === 0) {
    radix = 16;
    text = text.slice(2);
  } else if (text[0] === "#") {
    radix = 16;
    text = text.slice(1);
  } else if (text.length > 1 && text[0] === "0") {
    radix = 8;
    text = text.slice(1);
  }
  var valid = radix === 16 ? /^[0-9a-fA-F]+$/ : (radix === 8 ? /^[0-7]+$/ : /^\d+$/);
  if (!valid.test(text)) throw new Error("Invalid int value: " + value);
  var number = sign * parseInt(text, radix);
  if (number < -2147483648 || number > 2147483647) {
    throw new Error("Int value out of range: " + value);
  }
  return number;
}

function parseBooleanExtra(value) {
  var text = String(value).toLowerCase();
  if (text === "true" || text === "t") return true;
  if (text === "false" || text === "f") return false;
  return parseAndroidInt(text) !== 0;
}

function extraListValue(value, canonicalType) {
  var items = splitExtraValues(value);
  var elementType = canonicalType.replace(/\[\]$/, "").replace(/-list$/, "");
  var IntegerJava = Java.use("java.lang.Integer");
  var LongJava = Java.use("java.lang.Long");
  var FloatJava = Java.use("java.lang.Float");
  var DoubleJava = Java.use("java.lang.Double");
  var StringJava = Java.use("java.lang.String");
  return items.map(function(item) {
    if (elementType === "int") return IntegerJava.valueOf(parseAndroidInt(item));
    if (elementType === "long") return LongJava.valueOf(String(item));
    if (elementType === "float") return FloatJava.valueOf(String(item));
    if (elementType === "double") return DoubleJava.valueOf(String(item));
    return StringJava.$new(String(item));
  });
}

function extraArrayValue(value, canonicalType) {
  var items = splitExtraValues(value);
  var elementType = canonicalType.replace(/\[\]$/, "");
  var LongJava = Java.use("java.lang.Long");
  var FloatJava = Java.use("java.lang.Float");
  var DoubleJava = Java.use("java.lang.Double");
  return items.map(function(item) {
    if (elementType === "int") return parseAndroidInt(item);
    if (elementType === "long") return int64(String(item));
    if (elementType === "float") return FloatJava.valueOf(String(item)).floatValue();
    if (elementType === "double") return DoubleJava.valueOf(String(item)).doubleValue();
    return String(item);
  });
}

function serializeRecognizedExtra(value, typeName) {
  var canonical = null;
  var values = null;
  var scalarTypes = {
    "java.lang.String": "string", "java.lang.Boolean": "bool",
    "java.lang.Integer": "int", "java.lang.Long": "long",
    "java.lang.Float": "float", "java.lang.Double": "double",
    "android.content.ComponentName": "component"
  };
  if (scalarTypes[typeName] || typeName.indexOf("android.net.Uri$") === 0) {
    canonical = scalarTypes[typeName] || "uri";
    if (canonical === "component") {
      var componentValue = Java.cast(value, Java.use("android.content.ComponentName"));
      return { noxenType: canonical, value: String(componentValue.flattenToString()) };
    }
    return { noxenType: canonical, value: String(value) };
  }
  var arrayTypes = {
    "[I": "int[]", "[J": "long[]", "[F": "float[]", "[D": "double[]",
    "[Ljava.lang.String;": "string[]"
  };
  if (arrayTypes[typeName]) {
    canonical = arrayTypes[typeName];
    values = [];
    var ReflectArray = Java.use("java.lang.reflect.Array");
    var arrayLength = ReflectArray.getLength(value);
    for (var i = 0; i < arrayLength; i++) {
      var arrayItem = ReflectArray.get(value, i);
      values.push(canonical === "string[]" ? escapeExtraString(arrayItem) : String(arrayItem));
    }
  } else if (typeName === "java.util.ArrayList") {
    var elementClass = null;
    values = [];
    var listValue = Java.cast(value, Java.use("java.util.ArrayList"));
    for (var j = 0; j < listValue.size(); j++) {
      var item = listValue.get(j);
      if (item !== null && elementClass === null) {
        if (item.$className) {
          elementClass = String(item.$className);
        } else if (typeof item.getClass === "function") {
          elementClass = String(item.getClass().getName());
        }
      }
      values.push(item === null ? "null" : String(item));
    }
    var listTypes = {
      "java.lang.Integer": "int-list", "java.lang.Long": "long-list",
      "java.lang.Float": "float-list", "java.lang.Double": "double-list",
      "java.lang.String": "string-list"
    };
    canonical = listTypes[elementClass] || null;
    if (canonical === "string-list") {
      values = values.map(escapeExtraString);
    }
  }
  if (!canonical) return null;
  return { noxenType: canonical, value: values.join(",") };
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
    // Package set with setPackage(): limits an implicit intent to that app (null = any app).
    infoIntent.package = intent.getPackage() || null;
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
        var type = value ? String(value.getClass().getName()) : null;
        try {
          var recognized = value ? serializeRecognizedExtra(value, type) : null;
          extrasObj[key] = {
            type: type,
            value: recognized ? recognized.value : (value ? value.toString() : null)
          };
          if (recognized) extrasObj[key].noxenType = recognized.noxenType;
          else if (value === null) extrasObj[key].noxenType = "null";
        } catch (extraError) {
          extrasObj[key] = { type: type, value: value ? String(value) : null };
          send("[!] Extra serialization failed for " + key + " (" + type + "): " + extraError);
        }
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
        var eType = normalizeExtraType(mod.extraType);

        if (eType === "int") {
           intent.putExtra.overload("java.lang.String", "int").call(intent, key, parseAndroidInt(val));
        } 
        else if (eType === "bool" || eType === "boolean") {
           intent.putExtra.overload("java.lang.String", "boolean").call(intent, key, parseBooleanExtra(val));
        }
        else if (eType === "long") {
           intent.putExtra.overload("java.lang.String", "long").call(intent, key, int64(val));
        }
        else if (eType === "float") {
           var scalarFloat = Java.use("java.lang.Float").valueOf(String(val)).floatValue();
           intent.putExtra.overload("java.lang.String", "float").call(intent, key, scalarFloat);
        }
        else if (eType === "double") {
           var scalarDouble = Java.use("java.lang.Double").valueOf(String(val)).doubleValue();
           intent.putExtra.overload("java.lang.String", "double").call(intent, key, scalarDouble);
        }
        else if (eType === "null") {
           intent.putExtra.overload("java.lang.String", "java.lang.String").call(intent, key, null);
        }
        else if (eType === "uri") {
           intent.putExtra.overload("java.lang.String", "android.os.Parcelable")
             .call(intent, key, UriJava.parse(String(val)));
        }
        else if (eType === "component") {
           var ComponentNameJava = Java.use("android.content.ComponentName");
           var component = ComponentNameJava.unflattenFromString(String(val));
           if (component === null) throw new Error("Bad component name: " + val);
           intent.putExtra.overload("java.lang.String", "android.os.Parcelable")
             .call(intent, key, component);
        }
        else if (/\[\]$/.test(eType)) {
           var arrayItems = extraArrayValue(val, eType);
           var primitiveType = eType.slice(0, -2);
           var javaArrayType = primitiveType === "string" ? "java.lang.String" : primitiveType;
           var arrayValue = Java.array(javaArrayType, arrayItems);
           var arrayOverloads = {
             "int[]": "[I", "long[]": "[J", "float[]": "[F", "double[]": "[D",
             "string[]": "[Ljava.lang.String;"
           };
           intent.putExtra.overload("java.lang.String", arrayOverloads[eType])
             .call(intent, key, arrayValue);
        }
        else if (/-list$/.test(eType)) {
           var ArrayListJava = Java.use("java.util.ArrayList");
           var list = ArrayListJava.$new();
           extraListValue(val, eType).forEach(function(item) { list.add(item); });
           intent.putExtra.overload("java.lang.String", "java.io.Serializable")
             .call(intent, key, list);
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

// {name, level, definedBy} for a permission, or null. level is "unresolved" when
// Android cannot resolve it for this app: either no package defines it (another app
// could define and claim it) or its defining app is hidden by package visibility —
// the two are indistinguishable from inside the target. "unknown" means the base
// protection level is not one we map. definedBy is the defining package, if known.
function describePermission(pm, permName) {
  if (!permName) return null;
  var level = "unresolved";
  var definedBy = null;
  try {
    var info = pm.getPermissionInfo(permName, 0);
    if (info !== null) {
      level = PROTECTION_LEVELS[info.protectionLevel.value & 0xf] || "unknown";
      definedBy = info.packageName.value ? String(info.packageName.value) : null;
    }
  } catch (e) {}
  return { name: String(permName), level: level, definedBy: definedBy };
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
      if (targetType) result.targetType = targetType;
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
            GET_URI_PERMISSION_PATTERNS = 2048, GET_SIGNING_CERTIFICATES = 134217728;
        var flags = GET_ACTIVITIES | GET_RECEIVERS | GET_SERVICES | GET_PROVIDERS |
                    GET_META_DATA | GET_PERMISSIONS | GET_URI_PERMISSION_PATTERNS |
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
              perms.push({ name: nm, source: "requested", granted: granted,
                           level: dp.level, definedBy: dp.definedBy });
            }
          }
        });
        tryGet(function () {
          var defs = pi.permissions.value;
          if (defs !== null) {
            for (var i = 0; i < defs.length; i++) {
              var p = defs[i];
              perms.push({ name: String(p.name.value), source: "defined", granted: null,
                           level: (PROTECTION_LEVELS[p.protectionLevel.value & 0xf] || "unknown"),
                           definedBy: pkg });
            }
          }
        });
        out.permissions = perms;

        var ComponentName = Java.use("android.content.ComponentName");
        // PatternMatcher type → the manifest attribute that declares that kind of path.
        var PATH_MATCH = { 0: "path", 1: "pathPrefix", 2: "pathPattern", 3: "pathAdvancedPattern", 4: "pathSuffix" };
        function pathOf(pattern) {
          return { match: PATH_MATCH[pattern.getType()] || "path", path: s(pattern.getPath()) };
        }
        function pathPermissions(arr) {
          var res = [];
          if (arr === null) return res;
          for (var i = 0; i < arr.length; i++) {
            var pp = pathOf(arr[i]);
            pp.readPermission = describePermission(pm, s(arr[i].getReadPermission()));
            pp.writePermission = describePermission(pm, s(arr[i].getWritePermission()));
            res.push(pp);
          }
          return res;
        }
        function uriPatterns(arr) {
          var res = [];
          if (arr === null) return res;
          for (var i = 0; i < arr.length; i++) res.push(pathOf(arr[i]));
          return res;
        }
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
              // ProviderInfo has no `permission` field: a provider's android:permission is
              // split into readPermission/writePermission (collected below).
              permission: type === "provider" ? null : describePermission(pm, effectiveComponentPermission(ci)),
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
              c.readPermission = describePermission(pm, tryGet(function () { return s(ci.readPermission.value); }));
              c.writePermission = describePermission(pm, tryGet(function () { return s(ci.writePermission.value); }));
              c.pathPermissions = tryGet(function () { return pathPermissions(ci.pathPermissions.value); }) || [];
              c.grantUriPermissions = tryGet(function () { return ci.grantUriPermissions.value; });
              c.grantUriPatterns = tryGet(function () { return uriPatterns(ci.uriPermissionPatterns.value); }) || [];
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
