"""Operations on the running app. All methods execute on Textual's event loop.

The HTTP transport has no access to widgets or Frida. Slow I/O is delegated to
threads here; after an await, mutations recheck the state they were based on.
"""

import asyncio
import copy
import hashlib
import json
import math
import sqlite3
from contextvars import ContextVar
from uuid import uuid4

from textual.widgets import Input
from textual.worker import WorkerCancelled
from rich.text import Text

from noxen.agent_loader import ExtraScriptError, ExtraScriptSource, HookConfigError, load_extra_script, load_hook_config
from noxen.filters import FilterManager
from noxen.frida_session import SessionConfig
from noxen.intent_mods import (
    NESTED_INTENT_FIELDS, nested_mod_path, normalize_component, normalize_extra_type,
    parse_flag_value, validate_extra_value,
)
from noxen.monitor import missing_default_hooks, signature, validate_hook, validate_profiles
from noxen.monitor_ui import MonitorPane
from noxen.rendering import capture_order_label, entry_to_filter_context
from noxen.sender import SenderError, compare_sender_runs
from noxen.sender_capture import prepare_intent_request, prepare_component_request
from noxen.sender_service import endpoint_for_app


class OperationError(ValueError):
    pass


MAX_RESULT_BYTES = 512 * 1024


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
        self._enabled = False
        self._interception_changed = asyncio.Event()
        self.allow_control = False
        self._intercept_lock = asyncio.Lock()
        self._request_access = ContextVar("mcp_request_access", default=None)

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        if enabled != self._enabled:
            self._enabled = enabled
            self.interception_changed()

    def interception_changed(self):
        """Wake current waiters on the application loop."""
        self._interception_changed.set()
        self._interception_changed = asyncio.Event()

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
            "list_processes": self.list_processes,
            "list_applications": self.list_applications,
            "list_history": self.history, "export_history": self.export_history, "get_intent": self.intent,
            "set_input_anr_bypass": self.set_input_anr_bypass,
            "get_filters": self.filters, "set_filters": self.set_filters,
            "get_stack_settings": self.stack_settings, "set_stack_settings": self.set_stack_settings,
            "list_monitor_events": self.monitor_events, "get_monitor_event": self.monitor_event,
            "get_app_info": self.app_info, "refresh_app_info": self.refresh_app_info,
            "get_interception": self.interception,
            "wait_for_interception": self.wait_for_interception,
            "resolve_interception": self.resolve_interception, "set_intercept": self.set_intercept,
            "get_logs": self.logs,
            "list_crashes": self.list_crashes, "get_crash": self.get_crash,
            "clear_events": self.clear_events, "clear_logs": self.clear_logs,
            "get_monitor_profiles": self.profiles,
            "set_monitor_profile_enabled": self.set_profile_enabled,
            "set_monitor_profiles_enabled": self.set_profiles_enabled,
            "add_monitor_hook": self.add_monitor_hook,
            "save_monitor_profile": self.save_monitor_profile,
            "remove_monitor_profile": self.remove_monitor_profile,
            "restore_monitor_defaults": self.restore_monitor_defaults,
            "retry_monitor_hooks": self.retry_monitor_hooks,
            "connect": self.connect, "disconnect": self.disconnect,
            "get_sender": self.get_sender,
            "get_provider_interception": self.get_provider_interception,
            "resolve_provider_interception": self.resolve_provider_interception,
            "list_provider_calls": self.list_provider_calls,
            "check_sender_activity_context": self.check_sender_activity_context,
            "prepare_sender_request": self.prepare_sender_request,
            "prepare_sender_component": self.prepare_sender_component,
            "connect_sender": self.connect_sender,
            "disconnect_sender": self.disconnect_sender,
            "retry_sender_recording": self.retry_sender_recording,
            "list_sender_requests": self.list_sender_requests,
            "get_sender_request": self.get_sender_request,
            "save_sender_request": self.save_sender_request,
            "remove_sender_request": self.remove_sender_request,
            "execute_sender_request": self.execute_sender_request,
            "get_sender_run": self.get_sender_run,
            "list_sender_runs": self.list_sender_runs,
            "wait_for_sender_run": self.wait_for_sender_run,
            "cancel_sender_run": self.cancel_sender_run,
            "compare_sender_runs": self.compare_sender_runs,
        }
        context_token = self._request_access.set(_access_open)
        try:
            result = await operations[operation](**arguments)
        except SenderError as error:
            raise OperationError(f"sender_error: {error}") from None
        except (sqlite3.Error, OSError) as error:
            if "sender" not in operation:
                raise
            raise OperationError(f"sender_storage_error: {error}") from None
        finally:
            self._request_access.reset(context_token)
        result = json_value(result)
        if len(json.dumps(result, ensure_ascii=True, allow_nan=False)) > MAX_RESULT_BYTES:
            raise OperationError("result_too_large: use a smaller page or a narrower query")
        return result

    async def get_sender(self):
        return self.app.sender_service.status()

    async def check_sender_activity_context(self, expected_sender):
        return await self.app.sender_service.activity_context(expected_sender)

    async def prepare_sender_request(self, event_id, epoch, operation):
        snapshot = await self.intent(event_id, epoch)
        entry = snapshot["intent"]
        if entry.get("provider"):
            from noxen.providers import provider_request
            request = provider_request(entry["provider"])
            if operation != request["operation"]:
                raise OperationError("operation_mismatch: use the captured provider operation")
        else:
            request = prepare_intent_request(entry, operation)
        return {"request": request,
                "source": {"history_id": event_id}, "saved": False,
                "note": "Review and save before executing. No flags are added automatically."}

    async def prepare_sender_component(self, component_name, expected_connection):
        if expected_connection != self.connection_token():
            raise OperationError("state_changed: read get_status again")
        info = self.app._app_info or {}
        component = next((c for c in info.get("components", []) if c.get("name") == component_name), None)
        if component is None:
            raise OperationError("not_found: component is not present in the current Info app snapshot")
        return {"request": prepare_component_request(info.get("identity", {}).get("package"), component),
                "saved": False, "source": {"component": component_name}}

    async def connect_sender(self, device_id, package, pid, expected_sender, expected_connection):
        self.require_control(expected_connection)
        endpoint = endpoint_for_app(self.app, device_id, pid)
        result = await self.app.sender_service.connect(endpoint, package, expected_sender)
        try:
            self.require_control(expected_connection)
        except OperationError:
            if self.app.sender_service.token == result["token"]:
                await self.app.sender_service.disconnect(result["token"])
            raise
        return result

    async def disconnect_sender(self, expected_sender, expected_connection):
        self.require_control(expected_connection)
        return await self.app.sender_service.disconnect(expected_sender)

    async def retry_sender_recording(self, expected_connection):
        self.require_control(expected_connection)
        self.app.sender_service.retry_save()
        return self.app.sender_service.status()

    async def list_sender_requests(self):
        return {"requests": [{"id": r["id"], "name": r["name"], "revision": r["revision"],
                               "operation": r["request"].get("operation")} for r in self.app.db.sender_requests()]}

    async def get_sender_request(self, request_id):
        return self.app.sender_service.get_request(request_id)

    async def save_sender_request(self, name, request, expected_connection, request_id=None, revision=0):
        self.require_control(expected_connection)
        return self.app.sender_service.save_request(name, request, request_id, revision)

    async def remove_sender_request(self, request_id, revision, expected_connection):
        self.require_control(expected_connection)
        self.app.sender_service.remove_request(request_id, revision)
        return {"removed": request_id}

    async def execute_sender_request(self, request_id, revision, expected_sender, execution_key, expected_connection):
        self.require_control(expected_connection)
        return self.app.sender_service.execute(request_id, revision, expected_sender, execution_key)

    async def get_sender_run(self, run_id, section="all"):
        run = self.app.sender_service.get_run(run_id)
        if section == "all":
            return run
        keys = {"request": ("name", "request_id", "revision", "request"),
                "sender": ("device", "sender"),
                "result": ("state", "error", "result", "createdAt", "startedAt", "finishedAt", "receivedAt",
                           "durationMs", "cancellationRequested", "senderCrashId", "activityContext")}
        if section not in keys:
            raise SenderError("Unknown run section")
        return {"id": run["id"], **{key: run[key] for key in keys[section] if key in run}}

    async def list_sender_runs(self, before_id=None, limit=25):
        if not 1 <= limit <= 100:
            raise OperationError("invalid_limit: use a limit between 1 and 100")
        runs = await asyncio.to_thread(self.app.db.sender_run_summaries, "", limit, ("id", True), before_id)
        for run in runs:
            if run["id"] in self.app.sender_service.unsaved:
                run["state"] = self.app.sender_service.unsaved[run["id"]]["state"]
                run["saved"] = False
        return {"runs": runs,
                "next_before_id": runs[-1]["id"] if len(runs) == limit else None}

    async def wait_for_sender_run(self, run_id, timeout=30):
        return await self.app.sender_service.wait(run_id, timeout)

    async def cancel_sender_run(self, run_id, expected_sender, expected_connection):
        self.require_control(expected_connection)
        return await self.app.sender_service.cancel(run_id, expected_sender)

    async def compare_sender_runs(self, left_id, right_id):
        return await asyncio.to_thread(compare_sender_runs, self.app.sender_service.get_run(left_id),
                                       self.app.sender_service.get_run(right_id))

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
            "input_anr_bypass": self.input_anr_bypass_status(),
            "monitor_recording_error": self.pane.recording_error or None,
            "monitor_lost_events": self.pane.lost,
            "monitor_unsaved_events": self.pane.saved_unsaved,
            "monitor_incomplete_recordings": self.pane.interrupted_recordings,
        }

    def input_anr_bypass_status(self):
        app = self.app
        if not app._system_anr_bypass_enabled:
            return {"enabled": False, "state": "disabled", "installed_overloads": 0}
        if app.system_server_session is None:
            return {"enabled": True, "state": "waiting_for_connection", "installed_overloads": 0}
        return {"enabled": True, **app.system_server_session.installation_status()}

    async def set_input_anr_bypass(self, enabled, expected_connection):
        self.require_control(expected_connection)
        self.app.set_input_anr_bypass(enabled)
        return {"connection_token": self.connection_token(), "input_anr_bypass": self.input_anr_bypass_status()}

    async def devices(self):
        return {"devices": [{"id": d.id, "name": d.name, "type": d.type}
                            for d in self.app._home_devices],
                "source": "Last Home device scan; use refresh_devices to rediscover devices."}

    def _device_scan(self, device_id, expected_connection, limit):
        self.require_control(expected_connection)
        if not 1 <= limit <= 200:
            raise OperationError("invalid_limit: use a limit between 1 and 200")
        devices = self.app._home_devices
        if not any(d.id == device_id for d in devices):
            raise OperationError("unknown_device: call refresh_devices first")
        return devices

    @staticmethod
    def _resolve_device(devices, device_id):
        import frida
        resolver = getattr(devices, "get_device", None) or frida.get_device
        return resolver(device_id)

    async def list_applications(self, device_id, expected_connection, query="", limit=100):
        devices = self._device_scan(device_id, expected_connection, limit)

        def scan():
            term = query.casefold()
            matches = sorted(
                (a for a in self._resolve_device(devices, device_id).enumerate_applications()
                 if term in a.identifier.casefold() or term in a.name.casefold()),
                key=lambda a: a.identifier.casefold(),
            )
            return {"applications": [{"package": a.identifier, "name": a.name, "pid": a.pid or None}
                                     for a in matches[:limit]], "total_matches": len(matches)}

        return await asyncio.to_thread(scan)

    async def list_processes(self, device_id, expected_connection, query="", limit=100):
        devices = self._device_scan(device_id, expected_connection, limit)

        def scan():
            device = self._resolve_device(devices, device_id)
            processes = {p.pid: {"pid": p.pid, "name": p.name} for p in device.enumerate_processes()}
            for application in device.enumerate_applications():
                if application.pid in processes:
                    processes[application.pid]["package"] = application.identifier
            term = query.casefold()
            matches = sorted(
                (p for p in processes.values()
                 if term in p["name"].casefold() or term in p.get("package", "").casefold()),
                key=lambda p: (p["name"].casefold(), p["pid"]),
            )
            return {"processes": matches[:limit], "total_matches": len(matches)}

        return await asyncio.to_thread(scan)

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

    async def history(self, query="", before_id=None, epoch=None, limit=25, filter_revision=None):
        return await self._history_page(query, before_id, epoch, limit, filter_revision, full=False)

    async def export_history(self, query="", before_id=None, epoch=None, limit=25, filter_revision=None):
        return await self._history_page(query, before_id, epoch, limit, filter_revision, full=True)

    async def _history_page(self, query, before_id, epoch, limit, filter_revision, *, full):
        self.check_page("history", epoch, before_id, limit)
        app = self.app
        current_epoch = self.epoch("history")
        filters = None
        if filter_revision is not None:
            state = await self.filters("history")
            if filter_revision != state["revision"]:
                raise OperationError("filters_changed: reread get_filters and restart the query")
            filters = FilterManager.from_saved(state["filters"])
        # Reuse immutable search strings; searching/sorting never occupies the UI
        # thread or holds the capture lock. Only the bounded page is deep-copied.
        with app._history_lock:
            snapshot = [(e["id"], app._history_search_index.get(id(e), ""), e)
                        for e in app._all_intents]

        def search():
            normalized = query.lower()
            return sorted((row for row in snapshot if row[0] > 0
                           and (before_id is None or row[0] < before_id) and normalized in row[1]
                           and (filters is None or filters.is_visible(entry_to_filter_context(row[2])))),
                          key=lambda row: row[0], reverse=True)

        matches = await asyncio.to_thread(search)
        self.check_page("history", current_epoch, None, limit)
        if filter_revision is not None and filter_revision != (await self.filters("history"))["revision"]:
            raise OperationError("filters_changed: reread get_filters and restart the query")
        with app._history_lock:
            rows = []
            for _, _, entry in matches[:limit]:
                if full:
                    rows.append(copy.deepcopy(entry))
                    continue
                row = {k: copy.deepcopy(entry.get(k)) for k in ("id", "timestamp", "class", "method", "outcome")}
                row.update({k: copy.deepcopy(entry.get("intent", {}).get(k)) for k in ("component", "action")})
                if entry.get("provider"):
                    provider = entry["provider"]
                    row.update(event_type="provider", direction=provider.get("direction"),
                               uri=(provider.get("sentArguments") or provider.get("arguments") or {}).get("uri"))
                else:
                    row["event_type"] = "intent"
                row["capture_order"] = capture_order_label(entry)
                rows.append(row)
            unsaved = sum(row[0] <= 0 for row in snapshot)
        page = {"events": rows, "epoch": current_epoch, "unsaved_events": unsaved,
                "filter_revision": filter_revision, "next_before_id": None}
        if full:
            # Leave room for the actual cursor and the JSON list separators.
            size = len(json.dumps({**page, "events": [], "next_before_id": rows[0]["id"] if rows else None}))
            for index, row in enumerate(rows):
                size += len(json.dumps(json_value(row), ensure_ascii=True, allow_nan=False)) + 2
                if size > MAX_RESULT_BYTES:
                    if index == 0:
                        raise OperationError(f"result_too_large: History event #{row['id']} exceeds the export limit")
                    del rows[index:]
                    break
        if len(matches) > len(rows):
            page["next_before_id"] = rows[-1]["id"]
        return page

    def _filter_manager(self, scope):
        if scope == "intercept":
            return self.app.filter_manager
        if scope == "history":
            return self.app._history_filter_manager
        raise OperationError("invalid_scope: use intercept or history")

    async def filters(self, scope):
        filters = self._filter_manager(scope).export()
        revision = hashlib.sha256(json.dumps(filters, sort_keys=True).encode()).hexdigest()
        return {"scope": scope, "filters": filters, "revision": revision}

    async def set_filters(self, scope, filters, expected_revision, expected_connection):
        self.require_control(expected_connection)
        manager = self._filter_manager(scope)
        if expected_revision != (await self.filters(scope))["revision"]:
            raise OperationError("filters_changed: reread get_filters")
        ids = set()
        for item in filters:
            if (type(item.get("id")) is not int or item["id"] <= 0 or item["id"] in ids
                    or not isinstance(item.get("type"), str)
                    or type(item.get("enabled", True)) is not bool
                    or not item.get("rule") or FilterManager._normalize_saved_filter(item) is None):
                raise OperationError("invalid_filter: supply unique positive IDs and valid nonempty rules")
            ids.add(item["id"])
        normalized = FilterManager.from_saved(filters).export()
        persist = self.app.db.save_intercept_filters if scope == "intercept" else self.app.db.save_history_filters
        try:
            persist(normalized)
        except (OSError, sqlite3.Error) as error:
            raise OperationError(f"save_failed: {error}") from None
        manager.replace_all(normalized)
        if scope == "history":
            self.app._refresh_history_table()
        self.app._update_filter_count()
        return await self.filters(scope)

    async def stack_settings(self):
        app = self.app
        return {"intercept": {"enabled": app.show_stack, "depth": app.stack_depth},
                "history": {"enabled": app._history_show_stack, "depth": app._history_stack_depth}}

    async def set_stack_settings(self, scope, enabled, depth, expected_connection):
        self.require_control(expected_connection)
        if depth < 1:
            raise OperationError("invalid_depth: depth must be a positive integer")
        app = self.app
        if scope == "intercept":
            app.show_stack, app.stack_depth = enabled, depth
            app._refresh_intercept_display()
        elif scope == "history":
            app._history_show_stack, app._history_stack_depth = enabled, depth
            app._refresh_history_detail()
        else:
            raise OperationError("invalid_scope: use intercept or history")
        return await self.stack_settings()

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

    async def refresh_app_info(self, expected_connection):
        self.require_control(expected_connection)
        session = self.app.frida_session
        if session is None or not session.is_ready():
            raise OperationError("session_not_ready: wait for the Frida agent")
        try:
            snapshot = await self.app._fetch_app_info_worker(session).wait()
        except WorkerCancelled:
            snapshot = None
        if expected_connection != self.connection_token() or self.app.frida_session is not session:
            raise OperationError("state_changed: read get_status before refreshing Info app")
        if snapshot is None:
            raise OperationError("app_info_unavailable: refresh did not produce a new snapshot")
        return {"connection_token": expected_connection, "snapshot": copy.deepcopy(snapshot)}

    async def list_crashes(self, limit=25, before_id=None):
        if not 1 <= limit <= 100:
            raise OperationError("invalid_limit: use a limit between 1 and 100")
        if before_id is not None and before_id <= 0:
            raise OperationError("invalid_cursor: before_id must be positive")
        records = await asyncio.to_thread(self.app.db.list_crashes, limit + 1, before_id)
        return {
            "crashes": records[:limit],
            "next_before_id": records[limit - 1]["id"] if len(records) > limit else None,
        }

    async def get_crash(self, crash_id):
        crash = await asyncio.to_thread(self.app.db.get_crash, crash_id)
        if crash is None:
            raise OperationError("not_found: crash is not available in this project")
        return {"crash": crash}

    async def logs(self, limit=50, scope="application"):
        if not 1 <= limit <= 200:
            raise OperationError("invalid_limit: use a limit between 1 and 200")
        entries = (list(self.app._frida_session_logs) if scope == "session" and self.app.frida_session
                   else [] if scope == "session" else self.app._log_entries)
        return {"entries": [Text.from_markup(line).plain for line in entries[-limit:]],
                "connection_token": self.connection_token(), "includes_debug": True, "scope": scope}

    async def clear_logs(self, expected_connection):
        self.require_control(expected_connection)
        self.app._clear_application_logs()
        return {"cleared": True}

    async def clear_events(self, source, epoch, expected_connection):
        def check_current():
            self.require_control(expected_connection)
            self.check_page(source, epoch, None, 1)

        check_current()
        if source == "history":
            self.app.action_clear_history()
        else:
            def check_queued_clear():
                try:
                    check_current()
                except OperationError as error:
                    return error

            result = await self.pane.clear_events(check_queued_clear).wait()
            if isinstance(result, OperationError):
                raise result
            if not result:
                raise OperationError("clear_failed: Monitor events were not cleared")
        current_epoch = self.epoch(source)
        if current_epoch == epoch:
            raise OperationError("clear_failed: events were not cleared")
        return {"cleared": True, "epoch": current_epoch}

    async def interception(self):
        is_provider = bool((self.app._current_intercepted_entry or {}).get("provider"))
        return {"connection_token": self.connection_token(), "held": self.app._intent_blocked,
                "enabled": self.app._intercept_mode,
                "decision_id": self.app._current_decision_id,
                "editing": self.app._edit_mode,
                "captured_intent": copy.deepcopy(self.app._current_intercepted_entry),
                "event_type": "provider" if is_provider else "intent",
                "note": ("Use resolve_provider_interception with the provider connection and current decision ID. "
                         "Inspect reads a held Cursor response."
                         if is_provider else
                         "Use resolve_interception with modifications to edit and forward the captured Intent.")}

    async def get_provider_interception(self):
        return self.app.provider_service.status()

    async def resolve_provider_interception(self, provider_connection, decision_id, action,
                                            expected_connection, arguments=None):
        self.require_control(expected_connection)
        if self.app._edit_mode or self.app._edit_forward_pending:
            raise OperationError("draft_pending: finish or cancel the provider draft in the TUI")
        result = await self.app.provider_service.resolve(provider_connection, decision_id, action, arguments)
        self.app._provider_tick()
        return result

    async def list_provider_calls(self, before_id=None, limit=25):
        if not 1 <= limit <= 100:
            raise OperationError("invalid_limit: use a limit between 1 and 100")
        return {"calls": await asyncio.to_thread(self.app.db.provider_calls, before_id, limit)}

    async def wait_for_interception(self, expected_connection, after_decision_id=None, timeout_ms=10000):
        if not 1 <= timeout_ms <= 30000:
            raise OperationError("invalid_timeout: use a timeout between 1 and 30000 ms")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_ms / 1000
        access_open = self._request_access.get()
        app = self.app
        while True:
            if not self.enabled or (access_open is not None and not access_open()):
                raise OperationError("server_stopped: MCP access has been stopped")
            if expected_connection != self.connection_token():
                raise OperationError("state_changed: read get_status before waiting again")
            if not app._intercept_mode:
                raise OperationError("intercept_disabled: enable interception before waiting")
            decision_id = app._current_decision_id
            if app._intent_blocked and decision_id and decision_id != after_decision_id:
                return {**await self.interception(), "timed_out": False}
            remaining = deadline - loop.time()
            if remaining <= 0:
                return {"timed_out": True, "connection_token": expected_connection}
            try:
                await asyncio.wait_for(self._interception_changed.wait(), remaining)
            except asyncio.TimeoutError:
                continue

    def _intercept_session(self, expected_connection):
        self.require_control(expected_connection)
        session = self.app.frida_session
        if not session or not session.is_ready():
            raise OperationError("session_not_ready: wait for the Frida agent")
        return session

    def _intent_modifications(self, modifications):
        if len(modifications) > 64:
            raise OperationError("invalid_modification: at most 64 changes per Intent")
        mods = []
        for index, change in enumerate(modifications, 1):
            kind = change.get("type")
            prefix = f"invalid_modification: change {index}"
            if not isinstance(kind, str):
                raise OperationError(f"{prefix} requires a type")
            allowed = {
                "component": {"value"}, "action": {"value"}, "data": {"value"}, "mime": {"value"},
                "cat_add": {"value"}, "cat_rem": {"value"}, "flag_add": {"value"}, "flag_rem": {"value"},
                "extra_add": {"key", "value", "extra_type"}, "extra_rem": {"key"},
                **dict.fromkeys(NESTED_INTENT_FIELDS, {"key", "value"}),
            }.get(kind)
            fields = set(change) - {"type"}
            path = change.get("path")
            if kind in NESTED_INTENT_FIELDS and fields == {"path", "value"}:
                if (not isinstance(path, list) or not 1 <= len(path) <= 18
                        or any(not isinstance(part, str) and (type(part) is not int or part < 0) for part in path)):
                    raise OperationError(f"{prefix}: path must contain field names, keys or nonnegative item indexes")
            elif allowed is None or fields != allowed:
                raise OperationError(f"{prefix} has an unsupported type or incorrect fields")
            key, value, extra_type = (change.get(name, "") for name in ("key", "value", "extra_type"))
            if any(not isinstance(part, str) for part in (key, value, extra_type)):
                raise OperationError(f"{prefix} requires string values")
            try:
                if path is not None:
                    for part in path:
                        if isinstance(part, str):
                            part.encode("utf-8")
                    extra_type = json.dumps(path)
                key.encode("utf-8")
                value.encode("utf-8")
                if kind in {"component", "nested_component"}:
                    value = normalize_component(value)
            except ValueError as error:
                raise OperationError(f"{prefix}: {error}") from None
            if kind.startswith("extra_") and not key:
                raise OperationError(f"{prefix} requires a nonempty extra key")
            if kind == "extra_add":
                error = validate_extra_value(extra_type, value)
                if error:
                    raise OperationError(f"{prefix}: {error}")
                extra_type = normalize_extra_type(extra_type)
            if kind.startswith("flag_"):
                flag = parse_flag_value(value)
                if flag is None:
                    raise OperationError(f"{prefix}: flag must be a 32-bit integer or bit mask")
                value = str(flag)
            if kind in {"action", "data", "mime", "nested_action", "nested_data", "nested_mime"} and value == "":
                value = None  # MCP clears a text field with an empty string.
            mod = (kind, key, value, extra_type)
            if error := self.app._mod_safety_error(mod):
                raise OperationError(f"{prefix}: {error}")
            mods.append(mod)
        nested_keys = set()
        for kind, key, _, encoded_path in mods:
            if kind in NESTED_INTENT_FIELDS:
                path = nested_mod_path(key, encoded_path)
                if len(path) > 1 and path[0] == "extras":
                    nested_keys.add(path[1])
        if any(key in nested_keys for kind, key, _, _ in mods if kind in {"extra_add", "extra_rem"}):
            raise OperationError("invalid_modification: cannot edit and replace or remove the same Intent extra")
        return mods

    async def _resolve(self, session, action, decision_id, modifications=()):
        app = self.app
        if action == "off" and decision_id is None and app._current_decision_id is not None:
            raise OperationError("decision_id_required: pass expected_decision_id from get_interception")
        if decision_id != app._current_decision_id or (action != "off" and not app._intent_blocked):
            raise OperationError("hold_changed: read get_interception again")
        if app._edit_mode or app._edit_forward_pending or app._staged_mods:
            raise OperationError("draft_pending: finish or cancel the Intent draft in the TUI")
        entry = app._current_intercepted_entry
        if entry and entry.get("provider"):
            if modifications:
                raise OperationError("provider_arguments_required: use resolve_provider_interception for provider edits")
            if action == "off":
                await asyncio.to_thread(session.intercept_off)
                app.update_intercept_button(False)
            else:
                service = app.provider_service
                await service.resolve(service.connection, decision_id, action)
            app._provider_tick()
            return await self.interception()
        if modifications and entry is None:
            raise OperationError("capture_unavailable: cannot validate modifications without a captured Intent")
        mods = self._intent_modifications(modifications)
        resolved = await asyncio.to_thread(
            app._resolve_interception, session, action, decision_id,
            app._current_intercept_id, entry, mods,
        )
        if not resolved:
            raise OperationError("hold_changed: the agent declined the decision; read get_interception again")
        if mods:
            return {"connection_token": self.connection_token(), "held": app._intent_blocked,
                    "decision_id": app._current_decision_id, "event_id": entry["id"],
                    "outcome": entry.get("outcome"), "modification_error": entry.get("modification_error"),
                    "history_epoch": self.epoch("history")}
        return await self.interception()

    async def resolve_interception(self, action, decision_id, expected_connection, modifications=()):
        if action not in ("forward", "drop") or not decision_id:
            raise OperationError("invalid_decision: supply forward or drop and a decision_id")
        if modifications and action != "forward":
            raise OperationError("invalid_modification: modifications require forward")
        async with self._intercept_lock:
            session = self._intercept_session(expected_connection)
            result = await self._resolve(session, action, decision_id, modifications)
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
                "missing_builtin_profiles": [p["id"] for p in self.pane.missing_profiles()],
                "hook_states": [{"profile": key[0], "signature": key[1], "status": value}
                                for key, value in self.pane.statuses.items()]}

    def _editable_profiles(self, expected_revision, expected_connection):
        self.require_control(expected_connection)
        if self.app._connection_state == "connecting" or self.pane.finishing or self.pane.clearing:
            raise OperationError("busy: wait for the current operation to finish")
        if expected_revision != self.profile_revision():
            raise OperationError("profiles_changed: reread get_monitor_profiles")
        return copy.deepcopy(self.pane.profiles)

    def _save_profiles(self, profiles):
        try:
            profiles = validate_profiles(profiles)
        except ValueError as error:
            raise OperationError(f"invalid_profile: {error}") from None
        if profiles != self.pane.profiles and not self.pane.save(profiles):
            raise OperationError("save_failed: profiles were not updated")
        return {"revision": self.profile_revision(),
                "configuration": "requested; consult hook_states for installation results"}

    async def set_profile_enabled(self, profile_id, enabled, expected_revision, expected_connection):
        result = await self.set_profiles_enabled({profile_id: enabled}, expected_revision, expected_connection)
        return {**result, "enabled": enabled}

    async def set_profiles_enabled(self, states, expected_revision, expected_connection):
        profiles = self._editable_profiles(expected_revision, expected_connection)
        by_id = {profile["id"]: profile for profile in profiles}
        for profile_id, enabled in states.items():
            if profile_id not in by_id:
                raise OperationError(f"not_found: unknown profile {profile_id}")
            by_id[profile_id]["enabled"] = enabled
        return self._save_profiles(profiles)

    async def add_monitor_hook(self, profile_id, hook, expected_revision, expected_connection):
        profiles = self._editable_profiles(expected_revision, expected_connection)
        profile = next((p for p in profiles if p["id"] == profile_id), None)
        if profile is None:
            raise OperationError("not_found: unknown profile")
        try:
            hook = validate_hook(hook)
        except ValueError as error:
            raise OperationError(f"invalid_hook: {error}") from None
        overload = signature(hook)
        if any(signature(existing) == overload for existing in profile["hooks"]):
            raise OperationError("duplicate_hook: this overload already exists in the profile")
        profile["hooks"].append(hook)
        return {**self._save_profiles(profiles), "signature": overload, "enabled": profile["enabled"]}

    async def save_monitor_profile(self, profile, expected_revision, expected_connection):
        profiles = self._editable_profiles(expected_revision, expected_connection)
        index = next((i for i, existing in enumerate(profiles) if existing["id"] == profile.get("id")), len(profiles))
        profiles[index:index + 1] = [profile]
        return self._save_profiles(profiles)

    async def remove_monitor_profile(self, profile_id, expected_revision, expected_connection):
        profiles = self._editable_profiles(expected_revision, expected_connection)
        remaining = [p for p in profiles if p["id"] != profile_id]
        if len(remaining) == len(profiles):
            raise OperationError("not_found: unknown profile")
        return self._save_profiles(remaining)

    async def restore_monitor_defaults(self, profile_id, expected_revision, expected_connection):
        profiles = self._editable_profiles(expected_revision, expected_connection)
        profile = next((p for p in profiles if p["id"] == profile_id), None)
        if profile is None:
            default = next((p for p in self.pane.missing_profiles() if p["id"] == profile_id), None)
            if default is None:
                raise OperationError("not_found: unknown built-in profile")
            profiles.append(default)
            restored = len(default["hooks"])
        else:
            missing = missing_default_hooks(profile)
            profile["hooks"].extend(missing)
            restored = len(missing)
        return {**self._save_profiles(profiles), "restored_hooks": restored}

    async def retry_monitor_hooks(self, expected_revision, expected_connection):
        self._editable_profiles(expected_revision, expected_connection)
        session = self.app.frida_session
        if session is None or session is not self.pane.session or not session.is_ready():
            raise OperationError("session_not_ready: wait for the Frida agent")
        self.pane.apply_configuration()
        return {"configuration": "requested; consult hook_states for installation results"}

    async def connect(self, device_id, mode, target, expected_connection, hooks=None, extra_script=None):
        self.require_control(expected_connection)
        if self.app._connection_state != "disconnected":
            raise OperationError("busy: disconnect the current session first")
        if mode not in ("spawn", "attach_name", "attach_pid") or not target.strip():
            raise OperationError("invalid_target: choose spawn, attach_name or attach_pid and a target")
        devices = self.app._home_devices
        if not any(d.id == device_id for d in devices):
            raise OperationError("unknown_device: call refresh_devices first")
        script_path = self.app.query_one("#home_script_path", Input).value.strip() or None
        path = self.app.query_one("#home_hooks_path", Input).value.strip() or None
        config = SessionConfig(custom_hooks=path if hooks is None else None)
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
        try:
            if hooks is None:
                config.validated_hooks = await asyncio.to_thread(load_hook_config, path)
            else:
                config.validated_hooks = await asyncio.to_thread(load_hook_config, inline_hooks=hooks)
        except HookConfigError as error:
            raise OperationError(f"invalid_hook_config: {error}") from None
        if extra_script is None and script_path:
            try:
                config.extra_script_source = await asyncio.to_thread(load_extra_script, script_path)
            except ExtraScriptError as error:
                raise OperationError(f"invalid_extra_script: {error}") from None
            config.extra_script = config.extra_script_source.path
        elif extra_script:
            try:
                extra_script.encode("utf-8")
            except UnicodeError:
                raise OperationError("invalid_extra_script: JavaScript must be valid UTF-8") from None
            config.extra_script_source = ExtraScriptSource("mcp-extra-script.js", extra_script)
        self.require_control(expected_connection)
        current_path = self.app.query_one("#home_hooks_path", Input).value.strip() or None
        current_script_path = self.app.query_one("#home_script_path", Input).value.strip() or None
        if devices is not self.app._home_devices or (hooks is None and path != current_path):
            raise OperationError("state_changed: Home configuration changed; retry after reading status")
        if extra_script is None and script_path != current_script_path:
            raise OperationError("state_changed: the extra script selected in Home changed; retry")
        self.app._start_validated_connection(device_id, config, open_intercept=False)
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
