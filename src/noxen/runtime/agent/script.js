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

// Methods where the CALLER receives intents — attack surface = is the component exported?
var RECEIVING_METHODS = {
  "getIntent": true, "onNewIntent": true, "onActivityResult": true, "setResult": true,
  "onReceive": true, "onStartCommand": true, "onBind": true
};

function buildAttackSurface(methodName, intent, self, firstArg) {
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
      var exported;
      if (methodName === "onReceive") {
        exported = pm.getReceiverInfo(cn, 0).exported.value;
      } else if (methodName === "onStartCommand" || methodName === "onBind") {
        exported = pm.getServiceInfo(cn, 0).exported.value;
      } else {
        exported = pm.getActivityInfo(cn, 0).exported.value;
      }
      result.callerExported = exported;
    } else if (intent !== null) {
      result.intentExplicit = intent.getComponent() !== null;
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

function createHook(targetWrapper, className, methodName, overloadArgs) {
  const method = targetWrapper[methodName].overload.apply(targetWrapper[methodName], overloadArgs);
  const isBoolean = method.returnType.className === 'boolean';
  const isPendingIntent = className === 'android.app.PendingIntent';

  method.implementation = function () {
    var firstArg = arguments.length > 0 ? arguments[0] : null;

    if (methodName === "getIntent") {
        var resultIntent = method.apply(this, arguments);
        var as = buildAttackSurface(methodName, resultIntent, this, null);
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

    var as = buildAttackSurface(methodName, intent, this, firstArg);
    var shouldDrop = processIntercept(this.$className, methodName, intent, pendingIntentFlags, as);

    if (shouldDrop) return isBoolean ? false : null;

    try {
      return method.apply(this, arguments);
    } catch (e) {
      send("[!] Forward error in " + methodName + ": " + e);
      return isBoolean ? false : null;
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
  }
};
