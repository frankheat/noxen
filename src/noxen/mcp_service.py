"""Operations on the running app. All methods execute on Textual's event loop.

The HTTP transport has no access to widgets or Frida. Slow I/O is delegated to
threads here; after an await, mutations recheck the state they were based on.
"""

import asyncio
import copy
import hashlib
import json
import math
from contextvars import ContextVar
from uuid import uuid4

from textual.widgets import Input
from rich.text import Text

from noxen.agent_loader import load_hook_config
from noxen.frida_session import SessionConfig
from noxen.monitor_ui import MonitorPane
from noxen.rendering import capture_order_label


class OperationError(ValueError):
    pass


def json_value(value):
    """Preserve numbers a JSON client cannot represent without loss."""
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > 2**53 - 1:
        return {"$number": str(value), "kind": "integer"}
    if isinstance(value, float) and not math.isfinite(value):
        return {"$number": str(value), "kind": "float"}
    if isinstance(value, dict):
        return {str(key): json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_value(item) for item in value]
    return value


class MCPService:
    def __init__(self, app):
        self.app = app
        self.instance = uuid4().hex
        self.enabled = False
        self.allow_control = False
        self._intercept_lock = asyncio.Lock()
        self._request_access = ContextVar("mcp_request_access", default=None)

    @property
    def pane(self):
        return self.app.query_one(MonitorPane)

    def connection_token(self):
        app = self.app
        return f"{self.instance}:{app._connection_generation}:{app._connection_state}"

    def require_control(self, expected_connection):
        access_open = self._request_access.get()
        if not self.enabled or (access_open is not None and not access_open()):
            raise OperationError("server_stopped: MCP access has been stopped")
        if not self.allow_control:
            raise OperationError("control_disabled: enable Allow control in the MCP tab")
        if expected_connection != self.connection_token():
            raise OperationError("state_changed: read get_status before changing the session")
        if getattr(self.app, "_quit_in_progress", False):
            raise OperationError("closing: noxen is closing")

    def epoch(self, source):
        revision = (self.app._history_epoch if source == "history" else self.pane.events_epoch)
        return f"{self.instance}:{source}:{revision}"

    async def invoke(self, operation, _access_open=None, **arguments):
        if not self.enabled or (_access_open is not None and not _access_open()):
            raise OperationError("server_stopped: MCP access has been stopped")
        # Explicit catalog: never expose arbitrary application methods.
        operations = {
            "get_status": self.status, "list_devices": self.devices,
            "refresh_devices": self.refresh_devices,
            "list_history": self.history, "get_intent": self.intent,
            "list_monitor_events": self.monitor_events, "get_monitor_event": self.monitor_event,
            "get_app_info": self.app_info, "get_interception": self.interception,
            "resolve_interception": self.resolve_interception, "set_intercept": self.set_intercept,
            "get_logs": self.logs,
            "get_monitor_profiles": self.profiles,
            "set_monitor_profile_enabled": self.set_profile_enabled,
            "connect": self.connect, "disconnect": self.disconnect,
        }
        context_token = self._request_access.set(_access_open)
        try:
            result = await operations[operation](**arguments)
        finally:
            self._request_access.reset(context_token)
        result = json_value(result)
        if len(json.dumps(result, ensure_ascii=True, allow_nan=False).encode()) > 512 * 1024:
            raise OperationError("result_too_large: use a smaller page or a narrower query")
        return result

    async def status(self):
        app = self.app
        session = app.frida_session
        return {
            "instance": self.instance, "connection_token": self.connection_token(),
            "state": app._connection_state,
            "agent_ready": bool(session and session.is_ready()),
            "device": app._session_device_id,
            "target": app._session_config.target_label() if session else None,
            "allow_control": self.allow_control,
            "history_epoch": self.epoch("history"), "monitor_epoch": self.epoch("monitor"),
            "intent_held": app._intent_blocked,
            "monitor_recording_error": self.pane.recording_error or None,
            "monitor_lost_events": self.pane.lost,
            "monitor_unsaved_events": self.pane.saved_unsaved,
            "monitor_incomplete_recordings": self.pane.interrupted_recordings,
        }

    async def devices(self):
        return {"devices": [{"id": d.id, "name": d.name, "type": d.type}
                            for d in self.app._home_devices],
                "source": "Last Home device scan; use refresh_devices to rediscover devices."}

    async def refresh_devices(self, expected_connection):
        self.require_control(expected_connection)
        worker = self.app._populate_home_devices()
        generation = self.app._connect_scan_generation
        error = await worker.wait()
        if generation != self.app._connect_scan_generation:
            raise OperationError("scan_superseded: another device scan started")
        if error:
            raise OperationError(f"scan_failed: {error}")
        return await self.devices()

    def check_page(self, source, epoch, before_id, limit):
        if not 1 <= limit <= 100:
            raise OperationError("invalid_limit: use a limit between 1 and 100")
        if epoch is not None and epoch != self.epoch(source):
            raise OperationError("events_cleared: restart the query without a cursor")
        if before_id is not None and (before_id <= 0 or epoch is None):
            raise OperationError("invalid_cursor: before_id requires the epoch from the previous page")

    async def history(self, query="", before_id=None, epoch=None, limit=25):
        self.check_page("history", epoch, before_id, limit)
        app = self.app
        current_epoch = self.epoch("history")
        # Reuse immutable search strings; searching/sorting never occupies the UI
        # thread or holds the capture lock. Only the bounded page is deep-copied.
        with app._history_lock:
            snapshot = [(e["id"], app._history_search_index.get(id(e), ""), e)
                        for e in app._all_intents]

        def search():
            normalized = query.lower()
            return sorted((row for row in snapshot if row[0] > 0
                           and (before_id is None or row[0] < before_id) and normalized in row[1]),
                          key=lambda row: row[0], reverse=True)

        matches = await asyncio.to_thread(search)
        self.check_page("history", current_epoch, None, limit)
        with app._history_lock:
            rows = []
            for _, _, entry in matches[:limit]:
                row = {k: copy.deepcopy(entry.get(k)) for k in ("id", "timestamp", "class", "method", "outcome")}
                row.update({k: copy.deepcopy(entry.get("intent", {}).get(k)) for k in ("component", "action")})
                row["capture_order"] = capture_order_label(entry)
                rows.append(row)
            unsaved = sum(row[0] <= 0 for row in snapshot)
        return {"events": rows, "epoch": current_epoch, "unsaved_events": unsaved,
                "next_before_id": rows[-1]["id"] if len(matches) > limit else None}

    async def intent(self, event_id, epoch):
        self.check_page("history", epoch, None, 1)
        with self.app._history_lock:
            entry = next((e for e in self.app._all_intents if e.get("id") == event_id), None)
            if entry is None:
                raise OperationError("not_found: Intent no longer available")
            return {"epoch": epoch, "intent": copy.deepcopy(entry)}

    async def monitor_events(self, query="", before_id=None, epoch=None, limit=25):
        self.check_page("monitor", epoch, before_id, limit)
        current_epoch = self.epoch("monitor")
        if self.pane.clearing:
            raise OperationError("events_clearing: retry after clearing completes")
        events, more, _ = await asyncio.to_thread(
            self.app.db.monitor_event_page, query.lower(),
            None if before_id is None else (before_id, before_id), limit, sort=("id", True),
        )
        self.check_page("monitor", current_epoch, None, limit)
        fields = ("time", "class", "method", "profiles", "outcome")
        rows = [dict({k: e.get(k) for k in fields}, id=e["_db_id"], capture_order=capture_order_label(e)) for e in events]
        recording = self.pane.recording
        return {"events": rows, "epoch": current_epoch, "source": "persisted",
                "pending_events": len(recording.pending) if recording else 0,
                "recording_error": self.pane.recording_error or None,
                "next_before_id": rows[-1]["id"] if more else None}

    async def monitor_event(self, event_id, epoch):
        self.check_page("monitor", epoch, None, 1)
        events, _, _ = await asyncio.to_thread(
            self.app.db.monitor_event_page, "", (event_id + 1, event_id + 1), 1, sort=("id", True),
        )
        self.check_page("monitor", epoch, None, 1)
        if not events or events[0]["_db_id"] != event_id:
            raise OperationError("not_found: Monitor event no longer available")
        return {"epoch": epoch, "event": events[0]}

    async def app_info(self):
        return {"connection_token": self.connection_token(), "snapshot": copy.deepcopy(self.app._app_info)}

    async def logs(self, limit=50):
        if not 1 <= limit <= 200:
            raise OperationError("invalid_limit: use a limit between 1 and 200")
        return {"entries": [Text.from_markup(line).plain for line in self.app._log_entries[-limit:]],
                "connection_token": self.connection_token(), "includes_debug": True}

    async def interception(self):
        return {"connection_token": self.connection_token(), "held": self.app._intent_blocked,
                "enabled": self.app._intercept_mode,
                "decision_id": self.app._current_decision_id,
                "editing": self.app._edit_mode,
                "captured_intent": copy.deepcopy(self.app._current_intercepted_entry),
                "note": "Captured data, not the editor draft. MCP editing is not available yet."}

    def _intercept_session(self, expected_connection):
        self.require_control(expected_connection)
        session = self.app.frida_session
        if not session or not session.is_ready():
            raise OperationError("session_not_ready: wait for the Frida agent")
        return session

    async def _resolve(self, session, action, decision_id):
        app = self.app
        if decision_id != app._current_decision_id or (action != "off" and not app._intent_blocked):
            raise OperationError("hold_changed: read get_interception again")
        if app._edit_mode or app._edit_forward_pending or app._staged_mods:
            raise OperationError("draft_pending: finish or cancel the Intent draft in the TUI")
        resolved = await asyncio.to_thread(
            app._resolve_interception, session, action, decision_id,
            app._current_intercept_id, app._current_intercepted_entry, [],
        )
        if not resolved:
            raise OperationError("hold_changed: the agent declined the decision; read get_interception again")
        return await self.interception()

    async def resolve_interception(self, action, decision_id, expected_connection):
        if action not in ("forward", "drop") or not decision_id:
            raise OperationError("invalid_decision: supply forward or drop and a decision_id")
        async with self._intercept_lock:
            session = self._intercept_session(expected_connection)
            result = await self._resolve(session, action, decision_id)
            return {**result, "resolved_decision_id": decision_id, "action": action}

    async def set_intercept(self, enabled, expected_decision_id, expected_connection):
        async with self._intercept_lock:
            session = self._intercept_session(expected_connection)
            if not enabled:
                return await self._resolve(session, "off", expected_decision_id)
            await asyncio.to_thread(session.intercept_on)
            if session is self.app.frida_session and session.is_ready():
                self.app.update_intercept_button(True)
            return await self.interception()

    def profile_revision(self):
        return hashlib.sha256(json.dumps(self.pane.profiles, sort_keys=True).encode()).hexdigest()

    async def profiles(self):
        return {"revision": self.profile_revision(), "profiles": copy.deepcopy(self.pane.profiles),
                "hook_states": [{"profile": key[0], "signature": key[1], "status": value}
                                for key, value in self.pane.statuses.items()]}

    async def set_profile_enabled(self, profile_id, enabled, expected_revision, expected_connection):
        self.require_control(expected_connection)
        if self.app._connection_state == "connecting" or self.pane.finishing or self.pane.clearing:
            raise OperationError("busy: wait for the current operation to finish")
        if expected_revision != self.profile_revision():
            raise OperationError("profiles_changed: reread get_monitor_profiles")
        profiles = copy.deepcopy(self.pane.profiles)
        profile = next((p for p in profiles if p["id"] == profile_id), None)
        if profile is None:
            raise OperationError("not_found: unknown profile")
        if profile["enabled"] != enabled:
            profile["enabled"] = enabled
            if not self.pane.save(profiles):
                raise OperationError("save_failed: profile was not updated")
        return {"revision": self.profile_revision(), "enabled": enabled,
                "configuration": "requested; consult hook_states for installation results"}

    async def connect(self, device_id, mode, target, expected_connection):
        self.require_control(expected_connection)
        if self.app._connection_state != "disconnected":
            raise OperationError("busy: disconnect the current session first")
        if mode not in ("spawn", "attach_name", "attach_pid") or not target.strip():
            raise OperationError("invalid_target: choose spawn, attach_name or attach_pid and a target")
        devices = self.app._home_devices
        if not any(d.id == device_id for d in devices):
            raise OperationError("unknown_device: call refresh_devices first")
        if self.app.query_one("#home_script_path", Input).value.strip():
            raise OperationError("extra_script_selected: connect from Home when using an extra script")
        path = self.app.query_one("#home_hooks_path", Input).value.strip() or None
        config = SessionConfig(custom_hooks=path)
        if mode == "attach_pid":
            try:
                config.attach_pid = int(target)
                if config.attach_pid <= 0:
                    raise ValueError
            except ValueError:
                raise OperationError("invalid_pid: use a positive integer") from None
        elif mode == "spawn":
            config.spawn_package = target
        else:
            config.attach_name = target
        config.validated_hooks = await asyncio.to_thread(load_hook_config, path)
        self.require_control(expected_connection)
        if devices is not self.app._home_devices or path != (self.app.query_one("#home_hooks_path", Input).value.strip() or None):
            raise OperationError("state_changed: Home configuration changed; retry after reading status")
        if self.app.query_one("#home_script_path", Input).value.strip():
            raise OperationError("state_changed: an extra script was selected")
        self.app._start_validated_connection(device_id, config)
        return await self.status()

    async def disconnect(self, expected_connection):
        self.require_control(expected_connection)
        session = self.app.frida_session
        async with self.pane.recording_lock:
            self.require_control(expected_connection)
            await self.pane.stop_recording_feed(session)
            if session is self.app.frida_session:
                self.app._do_disconnect()
        return await self.status()
