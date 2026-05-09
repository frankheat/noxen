import threading
from dataclasses import dataclass

from noxen.agent_loader import load_agent_script, load_hook_config
from noxen.filters import FilterManager
from noxen.logging_ui import log_debug, log_error, log_info, log_success, log_warning
from noxen.rendering import payload_to_filter_context, render_intercept_block


@dataclass
class SessionConfig:
    spawn_package: str | None = None
    attach_name: str | None = None
    attach_pid: int | None = None
    custom_hooks: str | None = None
    extra_script: str | None = None

    def target_label(self) -> str:
        if self.spawn_package:
            return self.spawn_package
        if self.attach_name:
            return self.attach_name
        if self.attach_pid is not None:
            return f"PID {self.attach_pid}"
        return ""


class FridaSession:
    def __init__(
        self,
        config: SessionConfig,
        filter_manager: FilterManager,
        log_cb: callable,
        intercept_cb: callable,
        get_stack: callable,
        history_cb: callable = None,
        outcome_cb: callable = None,
        intercept_log_cb: callable = None,
        initial_intercept: bool = True,
        hold_start_cb: callable = None,
        hold_end_cb: callable = None,
    ):
        self._config = config
        self.filter_manager = filter_manager
        self.log_cb = log_cb
        self.intercept_cb = intercept_cb
        self.get_stack = get_stack
        self.history_cb = history_cb
        self.outcome_cb = outcome_cb
        self.intercept_log_cb = intercept_log_cb
        self.initial_intercept = initial_intercept
        self.hold_start_cb = hold_start_cb
        self.hold_end_cb = hold_end_cb
        self.api_level_cb = None
        self.connected_cb = None
        self.disconnected_cb = None

        self._script = None
        self._session = None
        self._device_id = None
        self._connect_thread = None
        self._lock = threading.Lock()
        self._generation = 0
        self._blocking_enabled = True
        self._intercept_counter = 0
        self._history_counter = 0

    def connect(self, device_id):
        with self._lock:
            self._device_id = device_id
            self._generation += 1
            generation = self._generation
            self._connect_thread = threading.Thread(
                target=self._start_session,
                args=(generation, device_id),
                daemon=True,
            )
            self._connect_thread.start()

    def _start_session(self, generation, device_id):
        hooks_result = load_hook_config(self._config.custom_hooks)
        hooks_data = hooks_result.hooks
        for message in hooks_result.messages:
            self.log_cb(message)

        try:
            import frida
            if self._is_stale(generation):
                return
            self.log_cb(log_info(f"Connecting to device {device_id}", "frida"))
            device = frida.get_device(device_id, timeout=5)

            pid = None
            should_resume = False
            session = None
            def close_local(script=None):
                self._detach_stale_session(
                    session,
                    script,
                    device=device,
                    spawned_pid=pid if should_resume else None,
                )

            if self._config.spawn_package:
                pid = device.spawn([self._config.spawn_package])
                session = device.attach(pid)
                session.on("detached", self._on_detached)
                should_resume = True
                self.log_cb(log_success(f"Spawned {self._config.spawn_package} (PID {pid})", "frida"))
            elif self._config.attach_name:
                session = device.attach(self._config.attach_name)
                session.on("detached", self._on_detached)
                pid = getattr(session, 'pid', None)
                pid_str = f" (PID {pid})" if pid else ""
                self.log_cb(log_success(f"Attached to \"{self._config.attach_name}\"{pid_str}", "frida"))
            elif self._config.attach_pid:
                session = device.attach(self._config.attach_pid)
                session.on("detached", self._on_detached)
                self.log_cb(log_success(f"Attached to PID {self._config.attach_pid}", "frida"))
            else:
                self.log_cb(log_error("No target specified", "frida"))
                return

            if not self._keep_if_current(generation, session=session):
                close_local()
                return

        except Exception as e:
            if self._is_stale(generation):
                return
            self.log_cb(log_error(f"Connection failed: {e}", "frida"))
            return

        try:
            if self._is_stale(generation):
                close_local()
                return
            script_result = load_agent_script(self._config.extra_script)
            code = script_result.code
            for message in script_result.messages:
                self.log_cb(message)
        except Exception as e:
            self._clear_if_current(generation, session=session)
            close_local()
            self.log_cb(log_error(f"Failed to load agent script: {e}", "frida"))
            return

        try:
            script = session.create_script(code)
            script.on("message", self.on_message)
            if not self._keep_if_current(generation, session=session, script=script):
                close_local(script)
                return

            script.load()
            if self._is_stale(generation):
                close_local(script)
                return

            script.exports_sync.proxy(hooks_data)
            if self._is_stale(generation):
                close_local(script)
                return

            try:
                sdk_int = script.exports_sync.get_sdk_int()
                if self.api_level_cb:
                    self.api_level_cb(sdk_int)
            except Exception:
                pass

            if not self.initial_intercept:
                self.intercept_off()

            if self._is_stale(generation):
                close_local(script)
                return

            if should_resume:
                device.resume(pid)

            if not self._is_stale(generation) and self.connected_cb:
                self.connected_cb()


        except Exception as e:
            if self._is_stale(generation):
                close_local(locals().get("script"))
                return
            self._clear_if_current(generation, session=session, script=locals().get("script"))
            close_local(locals().get("script"))
            self.log_cb(log_error(f"Failed to start session: {e}", "frida"))

    def _on_detached(self, reason, crash):
        msg = reason.replace("-", " ") if reason else "unknown reason"
        self.log_cb(log_warning(f"Session detached: {msg}", "frida"))
        with self._lock:
            self._script = None
            self._session = None
        if self.disconnected_cb:
            self.disconnected_cb()

    def _is_stale(self, generation) -> bool:
        with self._lock:
            return generation != self._generation

    def _keep_if_current(self, generation, session=None, script=None) -> bool:
        with self._lock:
            if generation != self._generation:
                return False
            if session is not None:
                self._session = session
            if script is not None:
                self._script = script
            return True

    def _clear_if_current(self, generation, session=None, script=None) -> None:
        with self._lock:
            if generation != self._generation:
                return
            if session is not None and self._session is session:
                self._session = None
            if script is not None and self._script is script:
                self._script = None

    @staticmethod
    def _detach_stale_session(session, script=None, device=None, spawned_pid=None) -> None:
        if script:
            try:
                script.exports_sync.interceptoff()
            except Exception:
                pass
        if session:
            try:
                session.detach()
            except Exception:
                pass
        if device and spawned_pid is not None:
            try:
                device.kill(spawned_pid)
            except Exception:
                try:
                    device.resume(spawned_pid)
                except Exception:
                    pass

    def on_message(self, message, data):
        show_stack, stack_depth = self.get_stack()

        if message["type"] == "send":
            payload = message["payload"]
            if isinstance(payload, dict):
                event_name = payload.get("noxenEvent")
                if event_name == "hold_start":
                    if self.hold_start_cb:
                        self.hold_start_cb(payload)
                    return
                if event_name == "hold_end":
                    if self.hold_end_cb:
                        self.hold_end_cb(payload)
                    return

                self._history_counter += 1
                db_id = None
                if self.history_cb:
                    try:
                        db_id = self.history_cb(payload, self._history_counter)
                    except Exception as e:
                        self.log_cb(log_warning(f"History callback failed: {e}", "history"))

                decision = payload.get("decision") if isinstance(payload.get("decision"), dict) else {}
                requires_decision = bool(decision.get("required")) if "required" in decision else self._blocking_enabled
                decision_id = decision.get("id")
                is_visible = self.filter_manager.is_visible(payload_to_filter_context(payload))

                if not requires_decision:
                    if self.outcome_cb and db_id:
                        self.outcome_cb(db_id, "forwarded")
                elif not is_visible or not self._blocking_enabled:
                    self._forward_async(decision_id, db_id)
                else:
                    self._intercept_counter += 1
                    rendered = render_intercept_block(
                        payload,
                        self._intercept_counter,
                        show_stack,
                        stack_depth,
                    )
                    if self.intercept_log_cb:
                        self.intercept_log_cb(rendered, db_id, decision_id)
                    else:
                        self.log_cb(rendered)
                    self.intercept_cb(True)
            else:
                self.log_cb(self._format_js_message(payload))
        elif message["type"] == "error":
            self.log_cb(log_error(f"JavaScript error: {message['description']}", "agent"))

    def _forward_async(self, decision_id, db_id):
        def _resume():
            try:
                resumed = self._script.exports_sync.forward(decision_id)
            except Exception as e:
                self.log_cb(log_warning(f"Auto-forward failed: {e}", "frida"))
                return
            if resumed and self.outcome_cb and db_id:
                self.outcome_cb(db_id, "forwarded")

        threading.Thread(target=_resume, daemon=True).start()

    @staticmethod
    def _format_js_message(text):
        if text.startswith("[!]"):
            return log_error(text[3:].strip(), "agent")
        if text.startswith("[*]") or text.startswith("[+]"):
            return log_success(text[3:].strip(), "agent")
        if text.startswith("[~]"):
            return log_warning(text[3:].strip(), "agent")
        return log_debug(text, "agent")

    def forward(self, decision_id=None):
        return bool(self._script.exports_sync.forward(decision_id))

    def drop(self, decision_id=None):
        return bool(self._script.exports_sync.drop(decision_id))

    def stage_mod(self, mod_type, key, val, extra_type, decision_id=None):
        return bool(self._script.exports_sync.stage_mod(mod_type, key, val, extra_type, decision_id))

    def intercept_on(self):
        self._blocking_enabled = True
        self._script.exports_sync.intercepton()

    def intercept_off(self):
        self._blocking_enabled = False
        self._script.exports_sync.interceptoff()

    def is_ready(self) -> bool:
        with self._lock:
            return self._script is not None

    def cleanup(self):
        with self._lock:
            script = self._script
            session = self._session
            self._script = None
            self._session = None
            self._generation += 1

        def perform_cleanup():
            if script:
                try:
                    script.exports_sync.interceptoff()
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
