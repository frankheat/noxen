const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");

const files = [
  ["agent/script.js", "src/noxen/runtime/agent/script.js"],
  ["agent/script_bundle.js", "src/noxen/runtime/agent/script_bundle.js"],
  ["agent/system_server.js", "src/noxen/runtime/agent/system_server.js"],
  ["agent/system_server_bundle.js", "src/noxen/runtime/agent/system_server_bundle.js"],
  ["config/hooks.json", "src/noxen/runtime/config/hooks.json"],
];

for (const [source, target] of files) {
  const sourcePath = path.join(root, source);
  const targetPath = path.join(root, target);
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.copyFileSync(sourcePath, targetPath);
}
