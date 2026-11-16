import JavaBridge from 'frida-java-bridge';
const Java = globalThis.Java !== undefined ? globalThis.Java : JavaBridge;
try { globalThis.Java = Java; } catch (_) {}
const sender = require('./sender.js').createSender();
rpc.exports = {senderIdentity: sender.identity, senderExecute: sender.execute, senderCancel: sender.cancel};
rpc.exports.senderActivityContext = sender.checkActivityContext;
