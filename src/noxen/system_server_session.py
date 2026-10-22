import threading
from dataclasses import dataclass

from noxen.agent_loader import load_system_server_script
from noxen.logging_ui import log_debug, log_error, log_info, log_success, log_warning


@dataclass
class SystemServerConfig:
    max_hold_ms: int = 120000


class SystemServerSession:
    def __init__(self, config: SystemServerConfig, log_cb: callable, device_resolver: callable = None):
        self.config = config
        self.log_cb = log_cb
        self.device_resolver = device_resolver
        self._device_id = None
        self._session = None
        self._script = None
        self._connect_thread = None
        self._connecting = False
        self._ready = threading.Event()
        self._lock = threading.Lock()
        self._rpc_lock = threading.Lock()
        self._generation = 0
        self._active_holds: dict[str, dict] = {}

    def connect(self, device_id: str) -> None:
        with self._lock:
            if self._device_id == device_id and (self._connecting or self._script is not None):
                return
            old_script, old_session = self._script, self._session
            if self._device_id is not None and self._device_id != device_id:
                self._active_holds.clear()
            self._device_id = device_id
            self._script = None
            self._session = None
            self._ready.clear()
            self._generation += 1
            generation = self._generation
            self._rpc_lock = threading.Lock()
            self._connecting = True
            worker = threading.Thread(
                target=self._start_session,
                args=(generation, device_id),
                daemon=True,
            )
            self._connect_thread = worker
        # No Frida operations under the state lock: detach may invoke callbacks.
        self._cleanup_resources_async(old_script, old_session)
        worker.start()

    def _is_current(self, generation: int) -> bool:
        with self._lock:
            return generation == self._generation

    def _start_session(self, generation: int, device_id: str) -> None:
        session = script = None
        keep_session = False
        try:
            import frida
            if not self._is_current(generation):
                return
            resolver = self.device_resolver or frida.get_device
            device = resolver(device_id, timeout=5)
            if not self._is_current(generation):
                return
            pid = self._find_system_server_pid(device)
            if not self._is_current(generation):
                return
            self.log_cb(log_info(f"Attaching to system_server (PID {pid})", "input-anr"))

            session = device.attach(pid)
            with self._lock:
                if generation != self._generation:
                    return
                self._session = session
            session.on("detached", lambda reason, crash: self._on_detached(
                generation, session, reason, crash
            ))
            if session.is_detached:
                self._on_detached(generation, session, "connection-terminated", None)
                return

            script_result = load_system_server_script()
            for message in script_result.messages:
                self.log_cb(message)
            if not self._is_current(generation):
                return

            script = session.create_script(script_result.code)
            with self._lock:
                if generation != self._generation or self._session is not session:
                    return
                self._script = script
            script.on("message", lambda message, data: self._on_script_message(
                generation, script, message, data
            ))
            script.load()
            if not self._is_current(generation):
                return
            script.exports_sync.init({"maxHoldMs": self.config.max_hold_ms})
            if not self._is_current(generation):
                return
            status = script.exports_sync.status()
            if session.is_detached:
                self._on_detached(generation, session, "connection-terminated", None)
                return

            with self._lock:
                if generation != self._generation or self._session is not session:
                    return
                self._ready.set()
                self._connecting = False
                keep_session = True

            self._sync_active_holds(generation)
            if self._is_current(generation):
                self._log_status(status)
        except Exception as e:
            keep_session = False
            with self._lock:
                current = generation == self._generation
                if current:
                    self._generation += 1
                    self._session = None
                    self._script = None
                    self._connecting = False
                    self._ready.clear()
                    self._active_holds.clear()
            if current:
                self.log_cb(log_warning(f"Input ANR bypass unavailable: {e}", "input-anr"))
        finally:
            if not keep_session:
                self._detach_stale_session(script, session)

    @staticmethod
    def _detach_stale_session(script, session) -> None:
        try:
            script.exports_sync.clear()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass

    def _cleanup_resources_async(self, script, session):
        if script is None and session is None:
            return None
        worker = threading.Thread(
            target=self._detach_stale_session, args=(script, session), daemon=True,
        )
        worker.start()
        return worker

    @staticmethod
    def _find_system_server_pid(device) -> int:
        for process in device.enumerate_processes():
            if process.name == "system_server":
                return process.pid
        raise RuntimeError("system_server process not found")

    def _on_message(self, message, _data) -> None:
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("noxenEvent") == "system_server_log":
                self.log_cb(format_system_server_log(payload))
            elif isinstance(payload, str) and payload.startswith("[system_server] WARNING:"):
                self.log_cb(log_warning(payload.replace("[system_server] ", "", 1).strip(), "system_server"))
            else:
                self.log_cb(log_debug(str(payload) if payload else "message received", "system_server"))
        elif message.get("type") == "error":
            self.log_cb(log_error(f"JavaScript error: {message.get('description')}", "system_server"))

    def _on_script_message(self, generation, script, message, data) -> None:
        with self._lock:
            if generation != self._generation or self._script is not script:
                return
        self._on_message(message, data)

    def _log_status(self, status: dict | None) -> None:
        status = status or {}
        installed = int(status.get("installedOverloads") or 0)
        missing = int(status.get("missingHooks") or 0)
        failed = int(status.get("failedHooks") or 0)

        if installed <= 0:
            self.log_cb(
                log_warning(
                    "Input ANR bypass is enabled, but no supported system_server hooks were installed",
                    "input-anr",
                )
            )
            return

        self.log_cb(
            log_success(
                f"Input ANR bypass enabled ({installed} overloads, {missing} missing, {failed} failed)",
                "input-anr",
            )
        )
        for hook in status.get("hooks", []):
            state = hook.get("status")
            name = f"{hook.get('className')}.{hook.get('methodName')}"
            count = int(hook.get("installed") or 0)
            if count > 0:
                self.log_cb(log_debug(f"{name}: {count} overload(s)", "input-anr"))
            elif state == "error":
                self.log_cb(log_warning(f"{name}: {hook.get('error') or 'failed'}", "input-anr"))

    def _on_detached(self, generation, session, reason, _crash) -> None:
        with self._lock:
            if generation != self._generation or self._session is not session:
                return
            self._generation += 1
            self._script = None
            self._session = None
            self._connecting = False
            self._ready.clear()
        msg = reason.replace("-", " ") if reason else "unknown reason"
        self.log_cb(log_warning(f"system_server detached: {msg}", "input-anr"))

    def hold_start(self, hold: dict) -> None:
        hold_id = str(hold.get("holdId") or "")
        if not hold_id:
            return
        hold = dict(hold)
        hold["timeoutMs"] = self.config.max_hold_ms
        with self._lock:
            self._active_holds[hold_id] = hold
            generation = self._generation
        self.log_cb(
            log_debug(
                f"Hold started: pid={hold.get('pid')} method={hold.get('methodName')} "
                f"class={hold.get('className')}",
                "input-anr",
            )
        )
        self._call_script_async("holdstart", hold, generation=generation)

    def hold_end(self, hold_id: str | None, pid: int | None = None) -> None:
        if not hold_id:
            return
        with self._lock:
            self._active_holds.pop(str(hold_id), None)
            generation = self._generation
        self.log_cb(log_debug(f"Hold ended: hold={hold_id} pid={pid}", "input-anr"))
        self._call_script_async("holdend", str(hold_id), pid, generation=generation)

    def _sync_active_holds(self, generation=None) -> None:
        with self._lock:
            if generation is not None and generation != self._generation:
                return
            generation = self._generation
            holds = list(self._active_holds.values())
        for hold in holds:
            self._call_script_async("holdstart", hold, generation=generation)

    def _call_script_async(self, method_name: str, *args, generation=None) -> None:
        with self._lock:
            if generation is not None and generation != self._generation:
                return
            if self._script is None or not self._ready.is_set():
                return
            script, generation = self._script, self._generation
            rpc_lock = self._rpc_lock
        threading.Thread(
            target=self._call_script, args=(generation, script, rpc_lock, method_name, args), daemon=True,
        ).start()

    def _call_script(self, generation, script, rpc_lock, method_name: str, args: tuple) -> None:
        # Serialize only this connection's hold RPCs, never Frida calls under the state lock.
        with rpc_lock:
            with self._lock:
                if generation != self._generation or self._script is not script or not self._ready.is_set():
                    return
                if method_name == "holdstart":
                    hold = args[0]
                    # Dispatch only the exact snapshot still registered as active.
                    if self._active_holds.get(str(hold.get("holdId") or "")) is not hold:
                        return
            try:
                getattr(script.exports_sync, method_name)(*args)
            except Exception as e:
                if self._is_current(generation):
                    self.log_cb(log_warning(f"Input ANR bypass RPC failed: {e}", "input-anr"))

    def cleanup(self) -> None:
        with self._lock:
            script = self._script
            session = self._session
            self._script = None
            self._session = None
            self._active_holds.clear()
            self._ready.clear()
            self._connecting = False
            self._generation += 1

        cleanup_thread = self._cleanup_resources_async(script, session)
        if cleanup_thread is not None:
            cleanup_thread.join(timeout=0.5)


def format_system_server_log(payload: dict) -> str:
    level = payload.get("level") or "info"
    message = payload.get("message") or ""
    if level == "success":
        return log_success(message, "system_server")
    if level == "warning":
        return log_warning(message, "system_server")
    if level == "error":
        return log_error(message, "system_server")
    if level == "debug":
        return log_debug(message, "system_server")
    return log_info(message, "system_server")
