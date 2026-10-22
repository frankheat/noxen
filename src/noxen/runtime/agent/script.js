import Java_bridge from 'frida-java-bridge';

// Frida >= 17 compatibility: Java bridge is no longer injected as a global.
// In Frida < 17 globalThis.Java is still set automatically; we reuse it to
// avoid double-loading. In >= 17 globalThis.Java is undefined, so we use the
// explicitly imported frida-java-bridge.
const Java = typeof globalThis.Java !== 'undefined' ? globalThis.Java : Java_bridge;
// Re-export as global so extra scripts evaluated in this runtime can use it.
// On Frida < 17 Java is a read-only built-in, so we skip this silently.
try { globalThis.Java = Java; } catch (_) {}

var lock = null;
var ObjectJava = null;
var UriJava = null; 

// State
var blockEnabled = true;
var waiting = false;
var activeDecisionId = null;
var activeIntentPresent = false;
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

function normalizeFloatingExtra(value) {
  var text = String(value).trim();
  var lower = text.toLowerCase();
  if (lower === "nan" || lower === "+nan" || lower === "-nan") return "NaN";
  if (lower === "infinity" || lower === "+infinity") return "Infinity";
  if (lower === "-infinity") return "-Infinity";
  return text;
}

function extraListValue(value, canonicalType) {
  var items = splitExtraValues(value);
  var elementType = canonicalType.replace(/\[\]$/, "").replace(/-list$/, "");
  var IntegerJava = Java.use("java.lang.Integer");
  var LongJava = Java.use("java.lang.Long");
  var FloatJava = Java.use("java.lang.Float");
  var DoubleJava = Java.use("java.lang.Double");
  return items.map(function(item) {
    if (elementType === "int") return IntegerJava.valueOf(parseAndroidInt(item));
    if (elementType === "long") return LongJava.valueOf(String(item));
    if (elementType === "float") return FloatJava.valueOf(normalizeFloatingExtra(item));
    if (elementType === "double") return DoubleJava.valueOf(normalizeFloatingExtra(item));
    return javaStringArgument(String(item));
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
    if (elementType === "float") return FloatJava.valueOf(normalizeFloatingExtra(item)).floatValue();
    if (elementType === "double") return DoubleJava.valueOf(normalizeFloatingExtra(item)).doubleValue();
    return javaStringArgument(String(item));
  });
}

// Intent extras are untrusted app data. Keep traversal deliberately small and
// deterministic: unknown objects are never reflected or stringified.
var EXTRA_MAX_DEPTH = 8;
var EXTRA_MAX_CONTAINER_ITEMS = 50;
var EXTRA_MAX_TOTAL_NODES = 300;
var EXTRA_MAX_STRING_LENGTH = 2048;
var EXTRA_MAX_VALUE_ERRORS = 3;

function createExtraSerializationContext() {
  return {
    seen: Java.use("java.util.IdentityHashMap").$new(),
    nextReferenceId: 1,
    nodes: 0
  };
}

function requireWellFormedText(text) {
  var invalid = typeof text.isWellFormed === "function" ? !text.isWellFormed()
    : /[\ud800-\udbff](?![\udc00-\udfff])|(?:^|[^\ud800-\udbff])[\udc00-\udfff]/.test(text);
  if (invalid) {
    // Never put a lone surrogate in a Frida message, including error messages.
    var error = new Error("String contains unpaired UTF-16 surrogates");
    error.name = "InvalidUTF16";
    throw error;
  }
  return text;
}

function javaStringArgument(value) {
  if (value === null || typeof value !== "string") return value;
  requireWellFormedText(value);
  // NewStringUTF treats an embedded NUL as the end. Keep the common path cheap.
  return value.indexOf("\u0000") === -1 ? value
    : Java.use("java.lang.String").$new(Java.array("char", value.split("")));
}

var capturedTextMethods = Object.create(null);

function capturedJavaText(value, className, methodName, index) {
  // Reflection returns Object rather than auto-unboxing String through the
  // bridge's lossy readUtf16String(). Only fixed framework getters call this.
  var indexed = index !== undefined;
  var key = className + ":" + methodName + (indexed ? ":int" : "");
  var method = capturedTextMethods[key];
  if (!method) {
    var types = indexed ? [Java.use("java.lang.Integer").TYPE.value] : [];
    method = Java.use(className).class.getMethod(methodName, Java.array("java.lang.Class", types));
    capturedTextMethods[key] = method;
  }
  var args = indexed ? [Java.use("java.lang.Integer").valueOf(index)] : [];
  return method.invoke(value, Java.array("java.lang.Object", args));
}

function boundedExtraText(value, isJavaString) {
  var text, length;
  if (typeof value === "string") {
    text = value;
    length = text.length;
  } else {
    var string = isJavaString ? value : capturedJavaText(value, "java.lang.Object", "toString");
    var env = Java.vm.getEnv();
    // Bundle keys are untrusted too: never pass a non-String to JNI string APIs.
    if (!string) throw new Error("Expected a Java String");
    // Keep the wrapper alive while JNI uses its handle, including across GC.
    var stringClass = Java.use("java.lang.String").class;
    var isString;
    try {
      isString = env.isInstanceOf(string.$h, stringClass.$h);
    } finally {
      stringClass.$dispose();
    }
    if (!isString) throw new Error("Expected a Java String");
    length = env.getStringLength(string.$h);
    var chars = env.getStringChars(string.$h);
    if (chars.isNull()) throw new Error("Java string is unavailable");
    try {
      // One extra unit lets us avoid splitting an emoji at the display limit.
      var units = new Uint16Array(chars.readByteArray(Math.min(length, EXTRA_MAX_STRING_LENGTH + 1) * 2));
      text = String.fromCharCode.apply(null, units);
    } finally {
      env.releaseStringChars(string.$h, chars);
    }
  }
  var end = Math.min(length, EXTRA_MAX_STRING_LENGTH);
  if (end < length && text.charCodeAt(end - 1) >= 0xd800 && text.charCodeAt(end - 1) <= 0xdbff &&
      text.charCodeAt(end) >= 0xdc00 && text.charCodeAt(end) <= 0xdfff) end -= 1;
  return { value: requireWellFormedText(text.slice(0, end)), truncated: end < length, originalLength: length };
}

function capturedTextField(value, className, methodName, index) {
  var text = capturedJavaText(value, className, methodName, index);
  return text === null ? null : boundedExtraText(text, true).value;
}

function extraTypeName(value) {
  if (value === null || typeof value === "undefined") return null;
  try {
    return String(value.getClass().getName());
  } catch (_) {
    try { return value.$className ? String(value.$className) : null; } catch (_) { return null; }
  }
}

function extraErrorKind(error) {
  try {
    if (error && error.$className) return String(error.$className);
    if (error && typeof error.getClass === "function") return String(error.getClass().getName());
    if (error && error.name) return String(error.name);
  } catch (_) {}
  return "error";
}

function reserveExtraNode(context, typeName, depth) {
  if (depth > EXTRA_MAX_DEPTH) {
    return { kind: "truncated", type: typeName, reason: "maximum depth reached" };
  }
  if (context.nodes >= EXTRA_MAX_TOTAL_NODES) {
    return { kind: "truncated", type: typeName, reason: "maximum node count reached" };
  }
  context.nodes += 1;
  return null;
}

function registerExtraContainer(value, typeName, context) {
  var existing = context.seen.get(value);
  if (existing !== null) {
    return {
      reference: {
        kind: "reference",
        type: typeName,
        referenceId: Number(typeof existing.intValue === "function" ? existing.intValue() : existing)
      }
    };
  }
  var referenceId = context.nextReferenceId++;
  context.seen.put(value, Java.use("java.lang.Integer").valueOf(referenceId));
  return { referenceId: referenceId };
}

function scalarExtraNode(value, typeName) {
  var scalarTypes = {
    "java.lang.String": ["String", "string"],
    "java.lang.Boolean": ["boolean", "bool"],
    "java.lang.Byte": ["byte", null],
    "java.lang.Short": ["short", null],
    "java.lang.Integer": ["int", "int"],
    "java.lang.Long": ["long", "long"],
    "java.lang.Float": ["float", "float"],
    "java.lang.Double": ["double", "double"],
    "java.lang.Character": ["char", null]
  };
  var scalar = scalarTypes[typeName];
  if (scalar) {
    var scalarValue = typeName === "java.lang.Character"
      ? Java.cast(value, Java.use("java.lang.Character")).charValue() : value;
    var text = boundedExtraText(scalarValue, typeName === "java.lang.String");
    var node = {
      kind: "scalar",
      type: typeName,
      displayType: scalar[0],
      value: text.value
    };
    if (scalar[1] && !text.truncated) node.noxenType = scalar[1];
    if (text.truncated) {
      node.truncated = true;
      node.originalLength = text.originalLength;
    }
    return node;
  }
  if (typeName === "android.content.ComponentName") {
    var component = Java.cast(value, Java.use("android.content.ComponentName"));
    var componentText = boundedExtraText(capturedJavaText(component, "android.content.ComponentName", "flattenToString"), true);
    var componentNode = {
      kind: "scalar", type: typeName, displayType: "Component",
      value: componentText.value
    };
    if (!componentText.truncated) componentNode.noxenType = "component";
    if (componentText.truncated) {
      componentNode.truncated = true;
      componentNode.originalLength = componentText.originalLength;
    }
    return componentNode;
  }
  if (typeName && (typeName === "android.net.Uri" || typeName.indexOf("android.net.Uri$") === 0)) {
    var uriText = boundedExtraText(value);
    var uriNode = { kind: "scalar", type: typeName, displayType: "URI", value: uriText.value };
    if (!uriText.truncated) uriNode.noxenType = "uri";
    if (uriText.truncated) {
      uriNode.truncated = true;
      uriNode.originalLength = uriText.originalLength;
    }
    return uriNode;
  }
  return null;
}

function serializeExtraArray(value, typeName, context, depth) {
  var registered = registerExtraContainer(value, typeName, context);
  if (registered.reference) return registered.reference;
  var node = {
    kind: "array", type: typeName, displayType: typeName,
    referenceId: registered.referenceId, count: 0, items: []
  };
  try {
    var ReflectArray = Java.use("java.lang.reflect.Array");
    var length = Number(ReflectArray.getLength(value));
    node.count = length;
    var captured = Math.min(length, EXTRA_MAX_CONTAINER_ITEMS);
    for (var i = 0; i < captured; i++) {
      node.items.push(serializeExtraNode(ReflectArray.get(value, i), context, depth + 1));
    }
    if (length > captured) node.omitted = length - captured;
  } catch (error) {
    node.error = "array inspection failed (" + extraErrorKind(error) + ")";
  }
  return node;
}

function serializeExtraList(value, typeName, context, depth) {
  var registered = registerExtraContainer(value, typeName, context);
  if (registered.reference) return registered.reference;
  var node = {
    kind: "list", type: typeName, displayType: "ArrayList",
    referenceId: registered.referenceId, count: 0, items: []
  };
  try {
    var list = Java.cast(value, Java.use("java.util.ArrayList"));
    var size = Number(list.size());
    node.count = size;
    var captured = Math.min(size, EXTRA_MAX_CONTAINER_ITEMS);
    for (var i = 0; i < captured; i++) {
      node.items.push(serializeExtraNode(list.get(i), context, depth + 1));
    }
    if (size > captured) node.omitted = size - captured;
  } catch (error) {
    node.error = "list inspection failed (" + extraErrorKind(error) + ")";
  }
  return node;
}

function serializeBundleNode(value, typeName, context, depth) {
  var registered = registerExtraContainer(value, typeName, context);
  if (registered.reference) return registered.reference;
  var node = {
    kind: "bundle", type: typeName, displayType: typeName === "android.os.PersistableBundle" ? "PersistableBundle" : "Bundle",
    referenceId: registered.referenceId, count: 0, items: []
  };
  try {
    var bundle = Java.cast(value, Java.use(typeName));
    var size = Number(bundle.size());
    node.count = size;
    var iterator = bundle.keySet().iterator();
    var captured = 0;
    var errors = 0;
    while (iterator.hasNext() && captured < EXTRA_MAX_CONTAINER_ITEMS) {
      var javaKey = iterator.next();
      var keyText = boundedExtraText(javaKey, true);
      var child;
      try {
        child = serializeExtraNode(bundle.get(javaKey), context, depth + 1);
      } catch (error) {
        errors += 1;
        child = {
          kind: "error", type: null,
          reason: "value could not be read (" + extraErrorKind(error) + ")"
        };
      }
      node.items.push({
        key: keyText.value,
        keyTruncated: keyText.truncated,
        keyOriginalLength: keyText.truncated ? keyText.originalLength : undefined,
        value: child
      });
      captured += 1;
      if (errors >= EXTRA_MAX_VALUE_ERRORS) {
        node.error = "inspection stopped after repeated value errors";
        break;
      }
    }
    if (size > captured) node.omitted = size - captured;
  } catch (error) {
    node.error = "bundle could not be read (" + extraErrorKind(error) + ")";
  }
  return node;
}

function readNestedIntent(value, node, field, reader) {
  try {
    node[field] = reader(value);
  } catch (error) {
    if (!node.errors) node.errors = [];
    node.errors.push(field + " could not be read (" + extraErrorKind(error) + ")");
  }
}

function serializeIntentNode(value, typeName, context, depth) {
  var registered = registerExtraContainer(value, typeName, context);
  if (registered.reference) return registered.reference;
  var intentValue = Java.cast(value, Java.use("android.content.Intent"));
  var node = {
    kind: "intent", type: typeName, displayType: "Intent",
    referenceId: registered.referenceId
  };
  readNestedIntent(intentValue, node, "component", function(intent) {
    var component = intent.getComponent();
    return component ? capturedTextField(component, "android.content.ComponentName", "flattenToString") : null;
  });
  readNestedIntent(intentValue, node, "action", function(intent) {
    return capturedTextField(intent, "android.content.Intent", "getAction");
  });
  readNestedIntent(intentValue, node, "data", function(intent) {
    return capturedTextField(intent, "android.content.Intent", "getDataString");
  });
  readNestedIntent(intentValue, node, "mimeType", function(intent) {
    return capturedTextField(intent, "android.content.Intent", "getType");
  });
  readNestedIntent(intentValue, node, "package", function(intent) {
    return capturedTextField(intent, "android.content.Intent", "getPackage");
  });
  readNestedIntent(intentValue, node, "flags", function(intent) { return Number(intent.getFlags()); });
  readNestedIntent(intentValue, node, "categories", function(intent) {
    var categories = [];
    var categorySet = intent.getCategories();
    if (categorySet === null) return categories;
    var iterator = categorySet.iterator();
    while (iterator.hasNext() && categories.length < EXTRA_MAX_CONTAINER_ITEMS) {
      categories.push(boundedExtraText(iterator.next(), true).value);
    }
    if (iterator.hasNext()) node.categoriesTruncated = true;
    return categories;
  });
  readNestedIntent(intentValue, node, "selector", function(intent) {
    var selector = intent.getSelector();
    return selector === null ? null : serializeExtraNode(selector, context, depth + 1);
  });
  readNestedIntent(intentValue, node, "clipData", function(intent) {
    var clip = intent.getClipData();
    return clip === null ? null : serializeExtraNode(clip, context, depth + 1);
  });
  readNestedIntent(intentValue, node, "extras", function(intent) {
    var extras = intent.getExtras();
    return extras === null ? null : serializeExtraNode(extras, context, depth + 1);
  });
  return node;
}

function serializeClipDataNode(value, typeName, context, depth) {
  var registered = registerExtraContainer(value, typeName, context);
  if (registered.reference) return registered.reference;
  var node = {
    kind: "clipdata", type: typeName, displayType: "ClipData",
    referenceId: registered.referenceId, count: 0, mimeTypes: [], items: []
  };
  try {
    var description = value.getDescription();
    if (description !== null) {
      var label = description.getLabel();
      if (label !== null) node.label = boundedExtraText(label).value;
      var mimeCount = Number(description.getMimeTypeCount());
      for (var m = 0; m < Math.min(mimeCount, EXTRA_MAX_CONTAINER_ITEMS); m++) {
        node.mimeTypes.push(capturedTextField(description, "android.content.ClipDescription", "getMimeType", m));
      }
      if (mimeCount > node.mimeTypes.length) node.mimeTypesOmitted = mimeCount - node.mimeTypes.length;
    }
  } catch (error) {
    node.descriptionError = "description could not be read (" + extraErrorKind(error) + ")";
  }
  try {
    node.count = Number(value.getItemCount());
    var captured = Math.min(node.count, EXTRA_MAX_CONTAINER_ITEMS);
    for (var i = 0; i < captured; i++) {
      if (context.nodes >= EXTRA_MAX_TOTAL_NODES) break;
      var itemLimit = reserveExtraNode(context, "android.content.ClipData$Item", depth + 1);
      if (itemLimit) break;
      var itemNode = { kind: "clipitem", type: "android.content.ClipData$Item", displayType: "Item" };
      node.items.push(itemNode);
      try {
        var item = value.getItemAt(i);
        readNestedIntent(item, itemNode, "text", function(value) {
          var text = value.getText();
          return text === null ? null : boundedExtraText(text).value;
        });
        readNestedIntent(item, itemNode, "html", function(value) {
          return capturedTextField(value, "android.content.ClipData$Item", "getHtmlText");
        });
        readNestedIntent(item, itemNode, "uri", function(value) {
          var uri = value.getUri();
          return uri === null ? null : boundedExtraText(uri).value;
        });
        readNestedIntent(item, itemNode, "intent", function(value) {
          var nested = value.getIntent();
          return nested === null ? null : serializeExtraNode(nested, context, depth + 2);
        });
      } catch (error) {
        itemNode.error = "item could not be read (" + extraErrorKind(error) + ")";
      }
    }
    if (node.count > node.items.length) node.omitted = node.count - node.items.length;
  } catch (error) {
    node.error = "ClipData could not be read (" + extraErrorKind(error) + ")";
  }
  return node;
}

function serializeExtraNode(value, context, depth) {
  if (value === null || typeof value === "undefined") {
    var nullLimit = reserveExtraNode(context, null, depth);
    return nullLimit || { kind: "null", type: null, displayType: "null", value: null };
  }
  var typeName = extraTypeName(value);
  var limit = reserveExtraNode(context, typeName, depth);
  if (limit) return limit;
  try {
    var scalar = scalarExtraNode(value, typeName);
    if (scalar) return scalar;
    if (typeName === "android.os.Bundle" || typeName === "android.os.PersistableBundle") {
      return serializeBundleNode(value, typeName, context, depth);
    }
    if (typeName === "android.content.Intent") {
      return serializeIntentNode(value, typeName, context, depth);
    }
    if (typeName === "android.content.ClipData") {
      return serializeClipDataNode(value, typeName, context, depth);
    }
    if (typeName && typeName[0] === "[") {
      return serializeExtraArray(value, typeName, context, depth);
    }
    if (typeName === "java.util.ArrayList") {
      return serializeExtraList(value, typeName, context, depth);
    }
    return { kind: "opaque", type: typeName, displayType: typeName || "Object" };
  } catch (error) {
    return {
      kind: "error", type: typeName,
      reason: "value serialization failed (" + extraErrorKind(error) + ")"
    };
  }
}

function legacyCollectionValue(node) {
  if (node.error || node.omitted || !node.items || node.items.length !== node.count || node.items.length === 0) {
    return null;
  }
  var canonical = null;
  if (node.kind === "array") {
    var arrayTypes = {
      "[I": "int[]", "[J": "long[]", "[F": "float[]", "[D": "double[]",
      "[Ljava.lang.String;": "string[]"
    };
    canonical = arrayTypes[node.type] || null;
  } else if (node.kind === "list") {
    var firstType = node.items[0].noxenType;
    var listTypes = {
      "int": "int-list", "long": "long-list", "float": "float-list",
      "double": "double-list", "string": "string-list"
    };
    canonical = listTypes[firstType] || null;
    for (var i = 0; canonical && i < node.items.length; i++) {
      if (node.items[i].kind !== "scalar" || node.items[i].noxenType !== firstType || node.items[i].truncated) {
        canonical = null;
      }
    }
  }
  if (!canonical) return null;
  var values = [];
  for (var j = 0; j < node.items.length; j++) {
    var item = node.items[j];
    if (item.kind !== "scalar" || item.truncated) return null;
    values.push(canonical === "string[]" || canonical === "string-list" ? escapeExtraString(item.value) : item.value);
  }
  return { noxenType: canonical, value: values.join(",") };
}

function extraNodeSummary(node) {
  if (!node) return null;
  if (node.kind === "null") return null;
  if (node.kind === "scalar") return node.value;
  if (node.kind === "bundle") return node.displayType + " (" + node.count + " items)";
  if (node.kind === "intent") {
    var count = node.extras && node.extras.count ? node.extras.count : 0;
    return "Intent (" + count + (count === 1 ? " extra)" : " extras)");
  }
  if (node.kind === "array" || node.kind === "list") {
    return node.displayType + " (" + node.count + " items)";
  }
  if (node.kind === "reference") return "reference to #" + node.referenceId;
  if (node.kind === "opaque") return "(opaque object)";
  if (node.kind === "truncated") return "(truncated: " + node.reason + ")";
  return "(unreadable value)";
}

function extraEnvelopeFromNode(node) {
  var envelope = {
    type: node ? node.type : null,
    value: extraNodeSummary(node),
    structuredVersion: 1,
    structured: node,
    editable: false
  };
  if (!node) return envelope;
  if (node.kind === "null") envelope.noxenType = "null";
  if (node.kind === "scalar" && node.noxenType && !node.truncated) {
    envelope.noxenType = node.noxenType;
    envelope.value = node.value;
    envelope.editable = node.noxenType !== "null";
  } else if (node.kind === "array" || node.kind === "list") {
    var collection = legacyCollectionValue(node);
    if (collection) {
      envelope.noxenType = collection.noxenType;
      envelope.value = collection.value;
      envelope.editable = true;
    }
  }
  return envelope;
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

function dumpIntent(intent, strictComponent) {
  var infoIntent = {}
  if (intent === null) return infoIntent;

  try {
    var component = intent.getComponent();
    var componentText = component === null ? null
      : boundedExtraText(capturedJavaText(component, "android.content.ComponentName", "flattenToString"), true);
    infoIntent.component = componentText === null ? null : componentText.value;
    if (componentText && componentText.truncated) {
      infoIntent.truncatedFields = ["component"];
      infoIntent.errors = ["component truncated (" + componentText.originalLength + " UTF-16 units)"];
    }
  } catch (e) {
    if (strictComponent) throw e;
    infoIntent.component = null;
    infoIntent.errors = ["component could not be read (" + extraErrorKind(e) + ")"];
    infoIntent.unreadableFields = ["component"];
  }
  [ ["action", "getAction"], ["data", "getDataString"], ["mimeType", "getType"], ["package", "getPackage"] ].forEach(function(field) {
    try {
      var raw = capturedJavaText(intent, "android.content.Intent", field[1]);
      var text = raw === null ? null : boundedExtraText(raw, true);
      infoIntent[field[0]] = text === null ? null : text.value;
      if (text && text.truncated) {
        if (!infoIntent.truncatedFields) infoIntent.truncatedFields = [];
        infoIntent.truncatedFields.push(field[0]);
        if (!infoIntent.errors) infoIntent.errors = [];
        infoIntent.errors.push(field[0] + " truncated (" + text.originalLength + " UTF-16 units)");
      }
    } catch (e) {
      infoIntent[field[0]] = null;
      if (!infoIntent.unreadableFields) infoIntent.unreadableFields = [];
      infoIntent.unreadableFields.push(field[0]);
      if (!infoIntent.errors) infoIntent.errors = [];
      infoIntent.errors.push(field[0] + " could not be read (" + extraErrorKind(e) + ")");
    }
  });
  try { infoIntent.flags = intent.getFlags(); } catch (e) { infoIntent.flags = 0; }

  try {
    var clip = intent.getClipData();
    infoIntent.clipData = clip === null
      ? null
      : serializeExtraNode(clip, createExtraSerializationContext(), 0);
  } catch (e) {
    infoIntent.clipData = {
      kind: "error", type: "android.content.ClipData",
      reason: "ClipData could not be read (" + extraErrorKind(e) + ")"
    };
  }

  // A selector is a second Intent used for routing when the base Intent has no
  // explicit component. Keep it structured and separate from the base payload:
  // merging the two would hide which fields Android actually used.
  try {
    var selector = intent.getSelector();
    infoIntent.selector = selector === null
      ? null
      : serializeExtraNode(selector, createExtraSerializationContext(), 0);
  } catch (e) {
    infoIntent.selector = {
      kind: "error", type: "android.content.Intent",
      reason: "selector could not be read (" + extraErrorKind(e) + ")"
    };
  }

  var catList = [];
  try {
    var cats = intent.getCategories();
    if (cats !== null) {
      var catIterator = cats.iterator();
      while (catIterator.hasNext() && catList.length < EXTRA_MAX_CONTAINER_ITEMS) {
        catList.push(boundedExtraText(catIterator.next(), true).value);
      }
      if (catIterator.hasNext()) infoIntent.categoriesTruncated = true;
    }
  } catch (e) {
    infoIntent.categoriesReadError = true;
    send("[!] Intent categories could not be read (" + extraErrorKind(e) + ")");
  }
  infoIntent.categories = catList;

  var extrasObj = Object.create(null);
  try {
    var extras = intent.getExtras();
    if (extras) {
      var context = createExtraSerializationContext();
      var root = serializeExtraNode(extras, context, 0);
      if (root && root.kind === "bundle") {
        for (var i = 0; i < root.items.length; i++) {
          var item = root.items[i];
          var capturedKey = item.key;
          if (Object.prototype.hasOwnProperty.call(extrasObj, capturedKey)) {
            var suffix = "…#" + (i + 1);
            capturedKey = capturedKey.slice(0, Math.max(0, EXTRA_MAX_STRING_LENGTH - suffix.length)) + suffix;
          }
          extrasObj[capturedKey] = extraEnvelopeFromNode(item.value);
          if (item.keyTruncated) {
            extrasObj[capturedKey].keyTruncated = true;
            extrasObj[capturedKey].editable = false;
          }
        }
        infoIntent.extrasMeta = {
          count: root.count,
          capturedCount: root.items.length,
          omitted: root.omitted || 0,
          error: root.error || null,
          referenceId: root.referenceId
        };
      } else if (root) {
        infoIntent.extrasMeta = { count: 0, capturedCount: 0, omitted: 0, error: extraNodeSummary(root) };
      }
    }
  } catch (e) {
    infoIntent.extrasMeta = {
      count: 0, capturedCount: 0, omitted: 0,
      error: "extras could not be read (" + extraErrorKind(e) + ")"
    };
    send("[!] Intent extras could not be read (" + extraErrorKind(e) + ")");
  }
  infoIntent.extras = extrasObj;
  return infoIntent
}

function applyModifications(intent) {
  if (!intent) {
    modQueue = [];
    return { ok: false, error: "Intent is unavailable" };
  }

  var error = null;
  try {
    // Android's setData() clears the MIME type and setType() clears the data URI.
    // Resolve both final values first, then update them atomically so changing one
    // field preserves the other.
    var dataOrMimeChanged = false;
    var finalData = null;
    var finalMimeType = null;
    for (var index = 0; index < modQueue.length; index++) {
      var queued = modQueue[index];
      if (queued.type !== "data" && queued.type !== "mime") continue;
      if (!dataOrMimeChanged) {
        finalData = intent.getData();
        finalMimeType = capturedJavaText(intent, "android.content.Intent", "getType");
        dataOrMimeChanged = true;
      }
      if (queued.type === "data") {
        if (!UriJava && queued.val !== "") throw new Error("android.net.Uri is unavailable");
        finalData = queued.val === "" ? null : UriJava.parse(javaStringArgument(queued.val));
      } else {
        finalMimeType = queued.val === "" ? null : javaStringArgument(queued.val);
      }
    }
    if (dataOrMimeChanged) intent.setDataAndType(finalData, finalMimeType);

    modQueue.forEach(function(mod) {
      if (mod.type === "action") {
        intent.setAction(mod.val === "" ? null : javaStringArgument(mod.val));
      }
      else if (mod.type === "component") {
        if (mod.val === "") {
          intent.setComponent(null);
        } else {
          var name = String(mod.val);
          var separator = name.indexOf("/");
          if (separator < 1 || separator === name.length - 1 || name.indexOf("/", separator + 1) !== -1 ||
              /[\s\x00-\x1f\x7f]/.test(name) || name.slice(separator + 1) === ".") {
            throw new Error("Component must use package/class syntax");
          }
          var component = Java.use("android.content.ComponentName").unflattenFromString(name);
          if (component === null) throw new Error("Bad component name: " + name);
          intent.setComponent(component);
        }
      }
      else if (mod.type === "data" || mod.type === "mime") { /* applied together above */ }
      else if (mod.type === "cat_add") {
        intent.addCategory(javaStringArgument(mod.val));
      }
      else if (mod.type === "cat_rem") {
        intent.removeCategory(javaStringArgument(mod.val));
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
        intent.removeExtra(javaStringArgument(mod.key));
      }
      else if (mod.type === "extra_add") {
        
        var key = javaStringArgument(mod.key);
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
           var scalarFloat = Java.use("java.lang.Float").valueOf(normalizeFloatingExtra(val)).floatValue();
           intent.putExtra.overload("java.lang.String", "float").call(intent, key, scalarFloat);
        }
        else if (eType === "double") {
           var scalarDouble = Java.use("java.lang.Double").valueOf(normalizeFloatingExtra(val)).doubleValue();
           intent.putExtra.overload("java.lang.String", "double").call(intent, key, scalarDouble);
        }
        else if (eType === "null") {
           intent.putExtra.overload("java.lang.String", "java.lang.String").call(intent, key, null);
        }
        else if (eType === "uri") {
           intent.putExtra.overload("java.lang.String", "android.os.Parcelable")
             .call(intent, key, UriJava.parse(javaStringArgument(String(val))));
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
           intent.putExtra.overload("java.lang.String", "java.lang.String").call(intent, key, javaStringArgument(String(val)));
        }
      }
    });
  } catch (e) {
    error = String(e).slice(0, 300);
    send("[!] Error applying modifications: " + e);
  } finally {
    modQueue = [];
  }
  return { ok: error === null, error: error };
}

// Methods where the CALLER receives intents — the exposed component is the caller.
var RECEIVING_METHODS = {
  "getIntent": true, "onNewIntent": true, "onActivityResult": true, "setResult": true,
  "onReceive": true, "onStartCommand": true, "onBind": true
};

// Known sending methods and the PackageManager type of their named components.
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

function componentIdentity(component) {
  if (component === null) return null;
  return String(component.getPackageName()) + "/" + String(component.getClassName());
}

// Read only the components actually named by the two objects. Never
// resolve an implicit Intent or choose which of these components will receive it.
function describeIntentComponents(intent, context, targetType) {
  var components = {};
  var pm = null;
  var cached = {};
  function describe(value) {
    if (value === null) return null;
    var cn = value.getComponent();
    if (cn === null) return null;
    var name = componentIdentity(cn);
    if (cached[name]) return cached[name];
    var details = { component: name };
    cached[name] = details;
    try {
      if (pm === null) pm = getPackageManagerSafe(context);
      if (pm === null) throw new Error("PackageManager unavailable");
      var info = componentInfoFor(pm, targetType, cn);
      details.exported = info.exported.value;
      details.permission = describePermission(pm, effectiveComponentPermission(info));
    } catch (e) {
      details.unavailable = true;
    }
    return details;
  }
  try {
    var base = describe(intent);
    if (base !== null) components.base = base;
  } catch (e) {}
  try {
    var selector = describe(intent.getSelector());
    if (selector !== null) components.selector = selector;
  } catch (e) {}
  return components;
}

function buildAttackSurface(methodName, intent, self, firstArg, sendPermission) {
  var result = {};
  try {
    var targetType = SENDING_TARGET_TYPE[methodName];
    var activityEvent = targetType === "activity" ||
      ["getIntent", "onNewIntent", "onActivityResult", "setResult"].indexOf(methodName) !== -1;
    var broadcastEvent = targetType === "receiver" || methodName === "onReceive";
    var serviceEvent = targetType === "service" || methodName === "onStartCommand" || methodName === "onBind";
    var sendContext = (self && self.getPackageManager) ? self : firstArg;
    if (activityEvent && intent !== null) {
      result.activityComponents = describeIntentComponents(intent, sendContext, "activity");
    }
    if (broadcastEvent && intent !== null) {
      result.broadcastComponents = describeIntentComponents(intent, sendContext, "receiver");
    }
    if (serviceEvent && intent !== null) {
      result.serviceComponents = describeIntentComponents(intent, sendContext, "service");
    }
    if (methodName === "sendBroadcast" || methodName === "sendOrderedBroadcast") {
      // Preserve the actual argument even when component/permission lookups fail.
      result.broadcastPermission = sendPermission === null ? null : (
        sendPermission === "" ? { name: "", level: "unresolved", definedBy: null }
          : describePermission(getPackageManagerSafe(sendContext), sendPermission)
      );
    }
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
      activeIntentPresent = intent !== null;
      resumeMode = "forward";
      modQueue = [];
    }

    var infoIntent = dumpIntent(intent);

    // --- SEND STACK TRACE ---
    send({
        "noxenEvent": "intent",
        "protocolVersion": 1,
        "className": className,
        "methodName": methodName,
        "stackTrace": getStackTrace(),
        "infoIntent": infoIntent,
        "pendingIntentFlags": pendingIntentFlags !== undefined ? pendingIntentFlags : null,
        "attackSurface": Object.assign({}, attackSurface || {}, { intentPresent: intent !== null }),
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
      if (modQueue.length > 0) {
        var modificationResult = applyModifications(intent);
        var resultingIntent = null;
        try {
          resultingIntent = dumpIntent(intent, true);
        } catch (snapshotError) {
          modificationResult.ok = false;
          modificationResult.error = (modificationResult.error || "") +
            " (resulting Intent could not be captured: " + String(snapshotError).slice(0, 150) + ")";
        }
        send({
          noxenEvent: "modification_result",
          decisionId: decisionId,
          ok: modificationResult.ok,
          error: modificationResult.error,
          infoIntent: resultingIntent
        });
      }
    }

    resumeMode = "forward";

  } catch (e) {
    send("[Blocking Error] " + e);
  } finally {
    if (isBlocking) {
      endHold(holdId);
      waiting = false;
      activeDecisionId = null;
      activeIntentPresent = false;
    }
  }

  return shouldDrop;
}

function matchesActiveDecision(decisionId) {
  return waiting && typeof decisionId === "string" && decisionId.length > 0 &&
    decisionId === activeDecisionId;
}

function normalizeRpcMods(mods) {
  if (!Array.isArray(mods)) throw new Error("modifications must be an array");

  var supported = {
    component: true, action: true, data: true, mime: true,
    cat_add: true, cat_rem: true,
    flag_add: true, flag_rem: true,
    extra_add: true, extra_rem: true
  };
  return mods.map(function (mod) {
    if (!mod || !supported[mod.type]) {
      throw new Error("unsupported modification type");
    }
    return {
      type: String(mod.type),
      key: requireWellFormedText(mod.key === null || mod.key === undefined ? "" : String(mod.key)),
      val: requireWellFormedText(mod.val === null || mod.val === undefined ? "" : String(mod.val)),
      extraType: mod.extraType === null || mod.extraType === undefined
        ? "" : requireWellFormedText(String(mod.extraType))
    };
  });
}

function resumeWithMods(mods, decisionId, disableInterception) {
  var normalized;
  try {
    normalized = normalizeRpcMods(mods);
  } catch (e) {
    send("[!] Invalid modification set: " + e);
    return false;
  }

  var resumed = false;
  try {
    Java.performNow(function () {
      if (matchesActiveDecision(decisionId) && lock) {
        if (normalized.length > 0 && !activeIntentPresent) return;
        // Replacing, instead of extending, the queue makes retries idempotent and
        // ensures the agent applies exactly the draft visible in the TUI.
        modQueue = normalized;
        if (disableInterception) blockEnabled = false;
        resumeMode = "forward";
        Java.synchronized(lock, function () { lock.notify(); });
        resumed = true;
      } else if (disableInterception && !waiting && (decisionId === null || decisionId === undefined)) {
        blockEnabled = false;
        resumed = true;
      }
    });
  } catch (e) {
    send("[!] Forward resume failed: " + e);
  }
  return resumed;
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
  const intentIndex = overloadArgs.indexOf('android.content.Intent');

  if (methodName === "getIntent" && returnType !== "android.content.Intent") {
    throw new Error("getIntent return type is " + (returnType || "unknown") + ", expected android.content.Intent");
  }

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
    } else if (intentIndex >= 0) {
      // The declared argument position also handles subclasses of Intent.
      intent = arguments[intentIndex];
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
      if (permArg !== null && permArg !== undefined) sendPermission = String(permArg);
    }

    var as = buildAttackSurface(methodName, intent, this, firstArg, sendPermission);
    var shouldDrop = processIntercept(this.$className, methodName, intent, pendingIntentFlags, as);

    if (shouldDrop) return defaultReturn(returnType);

    return method.apply(this, arguments);
  };
}

rpc.exports = {
  loadExtraScript: function (name, source) {
    // Use the same runtime/Java bridge, but preserve the extra file's name in errors.
    var exports = rpc.exports;
    var reserved = Object.keys(exports).map(function (key) { return [key, exports[key]]; });
    Script.evaluate(name, source);
    if (rpc.exports !== exports || reserved.some(function (entry) {
      return exports[entry[0]] !== entry[1];
    })) {
      throw new Error("Extra script replaced reserved noxen RPC exports; do not overwrite rpc.exports or existing methods");
    }
    return true;
  },
  proxy: function (hookConfig) {
    var report = { installed: 0, installedIndices: [], skipped: [], failed: [] };
    try {
      Java.perform(function () {
        try {
          send("[*] Initializing app hooks");
          ObjectJava = Java.use("java.lang.Object");
          UriJava = Java.use("android.net.Uri");

          if (lock === null) lock = ObjectJava.$new();

          var sdkInt = Java.use("android.os.Build$VERSION").SDK_INT.value;

          hookConfig.forEach(function(h, index) {
            var signature = "unknown signature";
            try {
              if (!h || typeof h.clazz !== "string" || typeof h.method !== "string" || !Array.isArray(h.args)) {
                throw new Error("invalid hook definition received by agent");
              }
              signature = h.clazz + "." + h.method + "(" + h.args.join(", ") + ")";
              if (h.minApi && sdkInt < h.minApi) {
                report.skipped.push({
                  index: index,
                  signature: signature,
                  reason: "requires API " + h.minApi + ", device API " + sdkInt
                });
                return;
              }
              var targetClass = Java.use(h.clazz);
              createHook(targetClass, h.clazz, h.method, h.args);
              report.installed += 1;
              report.installedIndices.push(index);
            } catch (e) {
              report.failed.push({
                index: index,
                signature: signature,
                error: String(e)
              });
            }
          });
        } catch (e) {
          report.fatal = String(e);
        }
        send({ noxenEvent: "hook_report", report: report });
      });
    } catch (e) {
      report.fatal = String(e);
      send({ noxenEvent: "hook_report", report: report });
    }
    // In spawn mode Java.perform cannot complete until the process is resumed.
    // Report completion asynchronously instead of blocking this RPC call.
    return { pending: true };
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

  forwardWithMods: function (mods, decisionId) {
    return resumeWithMods(mods, decisionId, false);
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
    if (matchesActiveDecision(decisionId) && activeIntentPresent) {
        try {
          var mod = normalizeRpcMods([{type: type, key: key, val: val, extraType: extraType}])[0];
          modQueue.push(mod);
          send("[+] Modification staged: " + mod.type);
        } catch (e) {
          send("[!] Invalid modification: " + e);
          return false;
        }
        return true;
    } else {
        send("[!] Error: No matching editable Intent is blocked.");
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

  interceptOffWithMods: function (mods, decisionId) {
    return resumeWithMods(mods, decisionId, true);
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
            GET_URI_PERMISSION_PATTERNS = 2048, GET_SIGNING_CERTIFICATES = 134217728,
            MATCH_DISABLED_COMPONENTS = 512;
        // Inventory includes disabled components; this is not a routing query.
        var flags = GET_ACTIVITIES | GET_RECEIVERS | GET_SERVICES | GET_PROVIDERS |
                    GET_META_DATA | GET_PERMISSIONS | GET_URI_PERMISSION_PATTERNS |
                    MATCH_DISABLED_COMPONENTS |
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
