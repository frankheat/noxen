import threading
from dataclasses import dataclass

from noxen.agent_loader import load_system_server_script
from noxen.logging_ui import log_debug, log_error, log_info, log_success, log_warning


@dataclass
class SystemServerConfig:
    max_hold_ms: int = 120000


class SystemServerSession:
    def __init__(self, config: SystemServerConfig, log_cb: callable):
        self.config = config
        self.log_cb = log_cb
        self._device_id = None
        self._session = None
        self._script = None
        self._connect_thread = None
        self._ready = threading.Event()
        self._lock = threading.Lock()
        self._generation = 0
        self._active_holds: dict[str, dict] = {}

    def connect(self, device_id: str) -> None:
        needs_cleanup = False
        with self._lock:
            needs_cleanup = self._device_id is not None and self._device_id != device_id
        if needs_cleanup:
            self.cleanup()

        with self._lock:
            if self._device_id == device_id and self._connect_thread and self._connect_thread.is_alive():
                return
            if self._device_id == device_id and self._script is not None:
                return
            self._device_id = device_id
            self._ready.clear()
            self._generation += 1
            generation = self._generation
            self._connect_thread = threading.Thread(
                target=self._start_session,
                args=(generation,),
                daemon=True,
            )
            self._connect_thread.start()

    def _start_session(self, generation: int) -> None:
        try:
            import frida
            device = frida.get_device(self._device_id, timeout=5)
            pid = self._find_system_server_pid(device)
            self.log_cb(log_info(f"Attaching to system_server (PID {pid})", "input-anr"))

            session = device.attach(pid)
            session.on("detached", self._on_detached)

            script_result = load_system_server_script()
            for message in script_result.messages:
                self.log_cb(message)

            script = session.create_script(script_result.code)
            script.on("message", self._on_message)
            script.load()
            script.exports_sync.init({"maxHoldMs": self.config.max_hold_ms})
            status = script.exports_sync.status()

            with self._lock:
                stale = generation != self._generation
                if not stale:
                    self._session = session
                    self._script = script
                    self._ready.set()
            if stale:
                self._detach_stale_session(script, session)
                return

            self._sync_active_holds()
            self._log_status(status)
        except Exception as e:
            self.log_cb(log_warning(f"Input ANR bypass unavailable: {e}", "input-anr"))
            self.cleanup()

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

    def _on_detached(self, reason, _crash) -> None:
        msg = reason.replace("-", " ") if reason else "unknown reason"
        self.log_cb(log_warning(f"system_server detached: {msg}", "input-anr"))
        with self._lock:
            self._script = None
            self._session = None
            self._ready.clear()

    def hold_start(self, hold: dict) -> None:
        hold_id = str(hold.get("holdId") or "")
        if not hold_id:
            return
        hold = dict(hold)
        hold["timeoutMs"] = self.config.max_hold_ms
        with self._lock:
            self._active_holds[hold_id] = hold
        self.log_cb(
            log_debug(
                f"Hold started: pid={hold.get('pid')} method={hold.get('methodName')} "
                f"class={hold.get('className')}",
                "input-anr",
            )
        )
        self._call_script_async("holdstart", hold)

    def hold_end(self, hold_id: str | None, pid: int | None = None) -> None:
        if not hold_id:
            return
        with self._lock:
            self._active_holds.pop(str(hold_id), None)
        self.log_cb(log_debug(f"Hold ended: hold={hold_id} pid={pid}", "input-anr"))
        self._call_script_async("holdend", str(hold_id), pid)

    def _sync_active_holds(self) -> None:
        with self._lock:
            holds = list(self._active_holds.values())
        for hold in holds:
            self._call_script_async("holdstart", hold)

    def _call_script_async(self, method_name: str, *args) -> None:
        with self._lock:
            if self._script is None or not self._ready.is_set():
                return
        threading.Thread(target=self._call_script, args=(method_name, args), daemon=True).start()

    def _call_script(self, method_name: str, args: tuple) -> None:
        with self._lock:
            script = self._script
        if script is None:
            return
        try:
            getattr(script.exports_sync, method_name)(*args)
        except Exception as e:
            self.log_cb(log_warning(f"Input ANR bypass RPC failed: {e}", "input-anr"))

    def cleanup(self) -> None:
        with self._lock:
            script = self._script
            session = self._session
            self._script = None
            self._session = None
            self._active_holds.clear()
            self._ready.clear()
            self._generation += 1

        def perform_cleanup() -> None:
            if script:
                try:
                    script.exports_sync.clear()
                except Exception:
                    pass
            if session:
                try:
                    session.detach()
                except Exception:
                    pass

        cleanup_thread = threading.Thread(target=perform_cleanup, daemon=True)
        cleanup_thread.start()
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
