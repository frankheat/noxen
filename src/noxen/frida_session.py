import threading
from dataclasses import dataclass

from noxen.agent_loader import ExtraScriptSource, HooksLoadResult, load_agent_script, load_hook_config
from noxen.filters import FilterManager
from noxen.logging_ui import log_debug, log_error, log_info, log_success, log_warning
from noxen.rendering import payload_to_filter_context, render_intercept_block


MODIFICATION_CONFIRM_TIMEOUT = 5
HOOK_REPORT_TIMEOUT = 30


@dataclass
class SessionConfig:
    spawn_package: str | None = None
    attach_name: str | None = None
    attach_pid: int | None = None
    custom_hooks: str | None = None
    validated_hooks: HooksLoadResult | None = None
    extra_script: str | None = None
    extra_script_source: ExtraScriptSource | None = None

    def target_label(self) -> str:
        if self.spawn_package:
            return self.spawn_package
        if self.attach_name:
            return self.attach_name
        if self.attach_pid is not None:
            return f"PID {self.attach_pid}"
        return ""


@dataclass
class ModificationResume:
    resumed: bool
    report: dict | None = None

    def __bool__(self) -> bool:
        return self.resumed


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
        self.hook_warning_cb = None
        self.connected_cb = None
        self.connection_failed_cb = None
        self.disconnected_cb = None

        self._script = None
        self._session = None
        self._device_id = None
        self._connect_thread = None
        self._hooks_result = None
        self._hook_report_event = None
        self._hook_report = None
        self.hook_registration_count = None
        self._lock = threading.Lock()
        self._generation = 0
        self._ready = False
        self._blocking_enabled = True
        self._intercept_counter = 0
        self._history_counter = 0
        self._modification_lock = threading.Lock()
        self._pending_modifications: dict[str, tuple[threading.Event, dict]] = {}

    def connect(self, device_id):
        with self._lock:
            self._device_id = device_id
            self._generation += 1
            self._ready = False
            self.hook_registration_count = None
            generation = self._generation
            self._connect_thread = threading.Thread(
                target=self._start_session,
                args=(generation, device_id),
                daemon=True,
            )
            self._connect_thread.start()

    def _start_session(self, generation, device_id):
        stage = "configuration"
        try:
            hooks_result = self._config.validated_hooks or load_hook_config(self._config.custom_hooks)
            hooks_data = hooks_result.hooks
            for message in hooks_result.messages:
                self.log_cb(message)

            stage = "extra-script" if self._config.extra_script or self._config.extra_script_source else "agent"
            script_result = load_agent_script(
                self._config.extra_script_source or self._config.extra_script
            )
            for message in script_result.messages:
                self.log_cb(message)

            stage = "device"
            import frida
            if self._is_stale(generation):
                return
            self.log_cb(log_info(f"Connecting to device {device_id}", "frida"))
            device = frida.get_device(device_id, timeout=5)
            if self._is_stale(generation):
                return

            pid = None
            should_resume = False
            resumed = False
            session = None
            def close_local(script=None):
                self._detach_stale_session(
                    session,
                    script,
                    device=device,
                    spawned_pid=pid if should_resume and not resumed else None,
                )

            if self._config.spawn_package:
                stage = "spawn"
                pid = device.spawn([self._config.spawn_package])
                should_resume = True
                if self._is_stale(generation):
                    close_local()
                    return
                session = device.attach(pid)
                session.on("detached", lambda reason, crash: self._on_detached(
                    reason, crash, generation
                ))
                self.log_cb(log_success(f"Spawned {self._config.spawn_package} (PID {pid})", "frida"))
            elif self._config.attach_name:
                stage = "attach"
                session = device.attach(self._config.attach_name)
                session.on("detached", lambda reason, crash: self._on_detached(
                    reason, crash, generation
                ))
                pid = getattr(session, 'pid', None)
                pid_str = f" (PID {pid})" if pid else ""
                self.log_cb(log_success(f"Attached to \"{self._config.attach_name}\"{pid_str}", "frida"))
            elif self._config.attach_pid:
                stage = "attach"
                session = device.attach(self._config.attach_pid)
                session.on("detached", lambda reason, crash: self._on_detached(
                    reason, crash, generation
                ))
                self.log_cb(log_success(f"Attached to PID {self._config.attach_pid}", "frida"))
            else:
                self._report_connection_failure(
                    generation,
                    "configuration",
                    ValueError("No target specified"),
                    "No target specified",
                )
                return

            if not self._keep_if_current(generation, session=session):
                close_local()
                return

        except Exception as e:
            # Cancellation suppresses feedback, not cleanup of local resources.
            if "close_local" in locals():
                close_local()
            if self._is_stale(generation):
                return
            self._report_connection_failure(
                generation, stage, e, f"Connection failed: {e}"
            )
            return

        stage = "agent"
        try:
            if self._is_stale(generation):
                close_local()
                return
            script = session.create_script(script_result.code)
            script.on("message", lambda message, data: self._on_script_message(
                message, data, generation, script
            ))
            if not self._keep_if_current(generation, session=session, script=script):
                close_local(script)
                return

            with self._lock:
                self._hook_report_event = threading.Event()
                self._hook_report = None

            script.load()
            if self._is_stale(generation):
                close_local(script)
                return

            if script_result.extra_script is not None:
                stage = "extra-script"
                extra = script_result.extra_script
                if script.exports_sync.load_extra_script(extra.path, extra.code) is not True:
                    raise RuntimeError("Extra script execution was not confirmed")
                self.log_cb(log_info(
                    f"Extra script initial code executed: {extra.path} (async callbacks may still be pending)",
                    "loader",
                ))
                if self._is_stale(generation):
                    close_local(script)
                    return

            stage = "hooks"
            self._hooks_result = hooks_result
            hook_report = script.exports_sync.proxy(hooks_data)
            if isinstance(hook_report, dict) and not hook_report.get("pending"):
                self._receive_hook_report(hook_report)
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

            stage = "resume"
            if should_resume:
                device.resume(pid)
                resumed = True

            stage = "hooks"
            report_event = self._hook_report_event
            if not report_event.wait(HOOK_REPORT_TIMEOUT):
                raise RuntimeError("Hook registration report timed out")
            if self._is_stale(generation):
                close_local(script)
                return
            with self._lock:
                report = self._hook_report
                self._hook_report_event = None
                self._hook_report = None
                still_attached = self._session is session and self._script is script
            if not still_attached:
                raise RuntimeError("Session detached before hook registration completed")
            if not isinstance(report, dict):
                raise RuntimeError("Hook registration report unavailable")
            if report.get("fatal"):
                self._log_hook_report(report, hooks_result)
                raise RuntimeError(f"Hook initialization failed: {report['fatal']}")
            installed = report.get("installed")
            if isinstance(installed, bool) or not isinstance(installed, int) or installed < 1:
                self._log_hook_report(report, hooks_result)
                raise RuntimeError("No hooks were installed")
            indices = report.get("installedIndices")
            if (not isinstance(indices, list) or len(indices) != installed
                    or any(isinstance(index, bool) or not isinstance(index, int)
                           or index < 0 or index >= len(hooks_data) for index in indices)
                    or len(set(indices)) != len(indices)
                    or not isinstance(report.get("skipped"), list)
                    or not isinstance(report.get("failed"), list)):
                raise RuntimeError("Malformed hook registration report")

            with self._lock:
                if generation != self._generation or self._session is not session:
                    close_after_lock = True
                else:
                    self._ready = True
                    self.hook_registration_count = installed
                    close_after_lock = False
            if close_after_lock:
                close_local(script)
                return

            if not self._is_stale(generation) and self.connected_cb:
                self.connected_cb()
            self._log_hook_report(report, hooks_result)


        except Exception as e:
            if self._is_stale(generation):
                close_local(locals().get("script"))
                return
            self._clear_if_current(generation, session=session, script=locals().get("script"))
            self._report_connection_failure(
                generation, stage, e, f"Failed to start session: {e}"
            )
            close_local(locals().get("script"))

    def _log_hook_report(self, report, hooks_result: HooksLoadResult) -> None:
        if not isinstance(report, dict):
            self.log_cb(log_warning("Hook registration report unavailable", "hooks"))
            return

        fatal = report.get("fatal")
        if fatal:
            self.log_cb(log_error(f"Hook initialization failed: {fatal}", "hooks"))
            return

        installed = int(report.get("installed") or 0)
        installed_indices = report.get("installedIndices")
        if not isinstance(installed_indices, list):
            installed_indices = []
        skipped = report.get("skipped") if isinstance(report.get("skipped"), list) else []
        failed = report.get("failed") if isinstance(report.get("failed"), list) else []

        def source_for(item) -> str:
            index = item.get("index") if isinstance(item, dict) else None
            if isinstance(index, int) and 0 <= index < len(hooks_result.sources):
                return hooks_result.sources[index]
            return f"hook[{index}]" if isinstance(index, int) else "hook"

        for item in skipped:
            if not isinstance(item, dict):
                continue
            reason = item.get("reason") or "not supported on this API level"
            signature = item.get("signature") or "unknown signature"
            self.log_cb(log_warning(
                f"Skipped {source_for(item)} ({signature}): {reason}", "hooks"
            ))

        for item in failed:
            if not isinstance(item, dict):
                continue
            signature = item.get("signature") or "unknown signature"
            error = item.get("error") or "registration failed"
            self.log_cb(log_error(
                f"Failed {source_for(item)} ({signature}): {error}", "hooks"
            ))

        summary = f"Hooks: {installed} installed, {len(skipped)} skipped, {len(failed)} failed"
        if failed or installed == 0:
            self.log_cb(log_warning(summary, "hooks"))
        else:
            self.log_cb(log_success(summary, "hooks"))

        no_custom_installed = False
        if hooks_result.custom_count:
            custom_installed = sum(
                1 for index in installed_indices
                if isinstance(index, int)
                and 0 <= index < len(hooks_result.sources)
                and hooks_result.sources[index].startswith("custom ")
            )
            if custom_installed == 0:
                no_custom_installed = True
                self.log_cb(log_warning("No custom hooks were installed", "hooks"))

        if self.hook_warning_cb and (failed or no_custom_installed):
            if no_custom_installed:
                warning = "No custom hooks were installed. See Log for details."
            else:
                count = len(failed)
                warning = f"Hook setup incomplete: {count} hook{'s' if count != 1 else ''} failed. See Log."
            try:
                self.hook_warning_cb(warning)
            except Exception as callback_error:
                self.log_cb(log_warning(
                    f"Hook warning callback failed: {callback_error}", "hooks"
                ))

    def _report_connection_failure(self, generation, stage, error, log_message) -> None:
        """Log and report a failure to establish the current session."""
        if self._is_stale(generation):
            return
        self.log_cb(log_error(log_message, "frida"))
        if self.connection_failed_cb:
            try:
                self.connection_failed_cb(stage, error)
            except Exception as callback_error:
                self.log_cb(log_warning(
                    f"Connection failure callback failed: {callback_error}", "frida"
                ))

    def _on_detached(self, reason, crash, generation):
        with self._lock:
            if generation != self._generation:
                return
            self._script = None
            self._session = None
            self._ready = False
            self.hook_registration_count = None
            initializing = self._hook_report_event is not None
            if initializing:
                self._hook_report_event.set()
        msg = reason.replace("-", " ") if reason else "unknown reason"
        self.log_cb(log_warning(f"Session detached: {msg}", "frida"))
        if not initializing and self.disconnected_cb:
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
                self._ready = False
                self.hook_registration_count = None

    def _on_script_message(self, message, data, generation, script):
        with self._lock:
            if generation != self._generation or self._script is not script:
                return
        self.on_message(message, data)

    def _receive_hook_report(self, report):
        with self._lock:
            if self._hook_report_event is not None and not self._hook_report_event.is_set():
                self._hook_report = report
                self._hook_report_event.set()

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
        if message["type"] == "send":
            payload = message["payload"]
            if isinstance(payload, dict):
                event_name = payload.get("noxenEvent")
                if event_name == "hook_report":
                    if self._hook_report_event is not None:
                        self._receive_hook_report(payload.get("report"))
                    elif self._hooks_result is not None:
                        self._log_hook_report(payload.get("report"), self._hooks_result)
                    return
                if event_name == "hold_start":
                    if self.hold_start_cb:
                        self.hold_start_cb(payload)
                    return
                if event_name == "hold_end":
                    if self.hold_end_cb:
                        self.hold_end_cb(payload)
                    return
                if event_name == "modification_result":
                    decision_id = payload.get("decisionId")
                    if isinstance(decision_id, str):
                        with self._modification_lock:
                            pending = self._pending_modifications.get(decision_id)
                            if pending:
                                event, result = pending
                                result.update(payload)
                                event.set()
                    return

                if event_name != "intent":
                    self.log_cb(self._format_js_message(payload))
                    return
                if not self._valid_intent_event(payload):
                    self.log_cb(log_warning(
                        "Ignored invalid Intent event: unsupported protocol or malformed payload", "agent"
                    ))
                    return

                self._history_counter += 1
                db_id = None
                if self.history_cb:
                    try:
                        db_id = self.history_cb(payload, self._history_counter)
                    except Exception as e:
                        self.log_cb(log_warning(f"History callback failed: {e}", "history"))

                decision = payload["decision"]
                requires_decision = decision["required"]
                decision_id = decision.get("id")
                is_visible = self.filter_manager.is_visible(payload_to_filter_context(payload))

                if not requires_decision:
                    if self.outcome_cb and db_id:
                        self.outcome_cb(db_id, "forwarded")
                elif not is_visible or not self._blocking_enabled:
                    self._forward_async(decision_id, db_id)
                else:
                    self._intercept_counter += 1
                    show_stack, stack_depth = self.get_stack()
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
            detail = message.get("stack") or message.get("description", "Unknown error")
            self.log_cb(log_error(f"JavaScript error: {detail}", "agent"))

    @staticmethod
    def _valid_intent_event(payload):
        """Validate the agent envelope without interpreting application extra values."""
        version = payload.get("protocolVersion")
        if type(version) is not int or version != 1:
            return False
        if not all(isinstance(payload.get(key), str) and payload[key].strip()
                   for key in ("className", "methodName")):
            return False
        if not isinstance(payload.get("infoIntent"), dict):
            return False
        stack = payload.get("stackTrace")
        if not isinstance(stack, list) or not all(isinstance(frame, str) for frame in stack):
            return False
        decision = payload.get("decision")
        if not isinstance(decision, dict) or type(decision.get("required")) is not bool:
            return False
        decision_id = decision.get("id")
        if decision["required"]:
            return isinstance(decision_id, str) and bool(decision_id.strip())
        return decision_id is None

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
        if not isinstance(text, str):
            return log_debug(str(text), "agent")
        if text.startswith("[!]"):
            return log_error(text[3:].strip(), "agent")
        if text.startswith("[*]") or text.startswith("[+]"):
            return log_success(text[3:].strip(), "agent")
        if text.startswith("[~]"):
            return log_warning(text[3:].strip(), "agent")
        return log_debug(text, "agent")

    def forward(self, decision_id=None):
        return bool(self._script.exports_sync.forward(decision_id))

    @staticmethod
    def _rpc_mods(mods):
        return [
            {"type": mod_type, "key": key, "val": value, "extraType": extra_type}
            for mod_type, key, value, extra_type in mods
        ]

    def forward_with_mods(self, mods, decision_id=None):
        return self._resume_with_mods("forward_with_mods", mods, decision_id)

    def _resume_with_mods(self, rpc_name, mods, decision_id):
        pending = None
        if mods and decision_id:
            pending = (threading.Event(), {})
            with self._modification_lock:
                if decision_id in self._pending_modifications:
                    return ModificationResume(False)
                self._pending_modifications[decision_id] = pending
        try:
            resumed = bool(getattr(self._script.exports_sync, rpc_name)(
                self._rpc_mods(mods), decision_id
            ))
            if not resumed or not mods:
                return ModificationResume(resumed)
            if pending is None or not pending[0].wait(timeout=MODIFICATION_CONFIRM_TIMEOUT):
                return ModificationResume(True)
            if not pending[1]:
                return ModificationResume(True)
            return ModificationResume(True, pending[1].copy())
        finally:
            if pending is not None:
                with self._modification_lock:
                    if self._pending_modifications.get(decision_id) is pending:
                        del self._pending_modifications[decision_id]

    def drop(self, decision_id=None):
        return bool(self._script.exports_sync.drop(decision_id))

    def stage_mod(self, mod_type, key, val, extra_type, decision_id=None):
        return bool(self._script.exports_sync.stage_mod(mod_type, key, val, extra_type, decision_id))

    def get_app_info(self):
        script = self._script
        if script is None:
            return None
        return script.exports_sync.get_app_info()

    def intercept_on(self):
        self._blocking_enabled = True
        self._script.exports_sync.intercepton()

    def intercept_off(self):
        self._blocking_enabled = False
        self._script.exports_sync.interceptoff()

    def intercept_off_with_mods(self, mods, decision_id=None):
        result = self._resume_with_mods("intercept_off_with_mods", mods, decision_id)
        disabled = bool(result)
        if disabled:
            self._blocking_enabled = False
        return result

    def is_ready(self) -> bool:
        with self._lock:
            return self._ready and self._script is not None

    def cleanup(self):
        with self._modification_lock:
            for event, _result in self._pending_modifications.values():
                event.set()
        with self._lock:
            if self._hook_report_event is not None:
                self._hook_report_event.set()
            script = self._script
            session = self._session
            self._script = None
            self._session = None
            self._ready = False
            self.hook_registration_count = None
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
