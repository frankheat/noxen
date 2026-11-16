"""Project Sender coordinator shared by TUI and MCP, owned by the app loop."""

import asyncio
import copy
import threading
from datetime import datetime, timezone
from uuid import uuid4

from noxen.sender import SenderError, validate_request


def now():
    return datetime.now(timezone.utc).isoformat()


async def sender_io(function, *args):
    """A blocked Android call must not hold up Python executor shutdown."""
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def publish(value, error):
        if not future.done():
            if error is not None:
                future.set_exception(error)
            else:
                future.set_result(value)

    def run():
        try:
            value, error = function(*args), None
        except Exception as exc:
            value, error = None, exc
        try:
            loop.call_soon_threadsafe(publish, value, error)
        except RuntimeError:
            pass  # App loop has closed; the durable run remains unknown.

    threading.Thread(target=run, name="noxen-sender", daemon=True).start()
    return await future


class SenderService:
    def __init__(self, db):
        self.db = db
        self.session = None
        self.identity = None
        self.token = uuid4().hex
        self.state = "disconnected"
        self.active_run = None
        self.task = None
        self.unsaved = {}
        self.error = None
        self.version = 0
        self.db.interrupt_sender_runs()

    def status(self):
        ready = bool(self.session and self.session.is_ready())
        return {"token": self.token, "state": self.state if ready or self.state == "connecting" else "disconnected",
                "identity": copy.deepcopy(self.identity), "device": self.session.device_id if self.session else None,
                "active_run": self.active_run, "unsaved_results": list(self.unsaved), "error": self.error}

    def require_token(self, token):
        if token != self.token:
            raise SenderError("Sender changed; read its status again")

    def validate_observer_config(self, device_id, config):
        """Reject known conflicts before cleanup, spawn or attaching another agent."""
        endpoint = self.session
        if endpoint is None:
            return
        if self.state == "connecting":
            raise SenderError("Wait for Sender to connect or disconnect it first")
        if not endpoint.is_ready():
            return
        if endpoint.device_id != device_id:
            raise SenderError("Disconnect Sender before changing the observer device")
        if endpoint.observer is not None:
            raise SenderError("Disconnect Sender before replacing its shared observer session")
        if config.spawn_package and config.spawn_package == self.identity["package"]:
            raise SenderError("Disconnect Sender before spawning its application")
        if config.attach_pid == endpoint.pid:
            raise SenderError("Disconnect the standalone Sender before attaching the observer to its process")

    def validate_observer_target(self, device_id, pid):
        endpoint = self.session
        if endpoint and endpoint.is_ready() and endpoint.observer is None:
            if endpoint.device_id != device_id:
                raise SenderError("Disconnect Sender before changing the observer device")
            if endpoint.pid == pid:
                raise SenderError("Disconnect the standalone Sender, connect the observer, then reuse its process as Sender")

    async def connect(self, endpoint, package, token):
        self.require_token(token)
        if self.state == "connecting" or self.active_run is not None:
            raise SenderError("Sender is busy")
        await self.disconnect(token)
        generation = self.token
        self.state = "connecting"
        self.session = endpoint
        loop = asyncio.get_running_loop()
        def detached(reason, crash):
            try:
                loop.call_soon_threadsafe(self._detached, endpoint, generation, package, reason, crash)
            except RuntimeError:
                pass
        endpoint.detached_cb = detached
        try:
            identity = await sender_io(endpoint.connect, package)
        except BaseException as error:
            if self.token == generation:
                self.session = None
                self.state, self.error = "disconnected", str(error)
            task = asyncio.create_task(sender_io(endpoint.close))
            task.add_done_callback(self._consume_close)
            raise
        if generation != self.token:
            await sender_io(endpoint.close)
            raise SenderError("Sender connection was superseded")
        self.session, self.identity = endpoint, identity
        self.state, self.error = "ready", None
        return self.status()

    def _detached(self, endpoint, token, package, reason, crash):
        if self.token != token or self.session is not endpoint:
            return
        crash_id = None
        if crash is not None:
            report = crash.report or ""
            snapshot = {"timestamp": now(), "device": endpoint.device_id, "target": package,
                        "role": "sender", "reason": reason, "pid": crash.pid,
                        "captureSessionNumber": None, "captureSession": None,
                        "process": (crash.process_name or "")[:512], "summary": (crash.summary or "")[:512],
                        "report": report[:32768], "report_truncated": len(report) > 32768}
            try:
                crash_id = self.db.save_crash(snapshot)
            except Exception as error:
                self.error = f"Sender crash could not be saved: {error}"
        if self.active_run is not None:
            run = self.get_run(self.active_run)
            run.update(state="unknown", error=f"Sender detached: {reason}", receivedAt=now())
            if crash_id is not None:
                run["senderCrashId"] = crash_id
            self._save_result(run)
            self.active_run = None
        self.token = uuid4().hex
        self.session = None
        self.state = "disconnected"

    async def disconnect(self, token):
        self.require_token(token)
        self.token = uuid4().hex
        old, self.session = self.session, None
        self.state = "disconnected"
        if self.active_run is not None:
            run = self.get_run(self.active_run)
            run.update(state="unknown", error="Sender disconnected; the operation may still complete", receivedAt=now())
            self._save_result(run)
            self.active_run = None
        if old:
            # Detach may wait for an in-flight call. Do not stall the controller.
            task = asyncio.create_task(sender_io(old.close))
            task.add_done_callback(self._consume_close)
        return self.status()

    def _consume_close(self, task):
        if not task.cancelled():
            error = task.exception()
            if error:
                self.error = f"Sender detach failed: {error}"

    def save_request(self, name, request, request_id=None, revision=0):
        if not isinstance(name, str) or not name.strip() or len(name) > 200 or not name.isprintable():
            raise SenderError("Request name must contain 1–200 printable characters")
        valid = validate_request(request)
        if request_id is None:
            if revision != 0:
                raise SenderError("New requests require revision 0")
            request_id = uuid4().hex
        elif type(revision) is not int or revision < 1:
            raise SenderError("Existing requests require their current revision")
        try:
            revision = self.db.save_sender_request(request_id, revision, name, valid)
        except ValueError as error:
            raise SenderError(str(error)) from None
        self.version += 1
        return dict(id=request_id, revision=revision, name=name, request=valid)

    def remove_request(self, request_id, revision):
        try:
            self.db.remove_sender_request(request_id, revision)
        except ValueError as error:
            raise SenderError(str(error)) from None
        self.version += 1

    def get_request(self, request_id):
        request = self.db.sender_request(request_id)
        if request is None:
            raise SenderError("Unknown Sender request")
        return request

    def get_run(self, run_id):
        run = self.unsaved.get(run_id) or self.db.sender_run(run_id=run_id)
        if run is None:
            raise SenderError("Unknown Sender run")
        run = copy.deepcopy(run)
        if run["request"].get("operation") == "startActivity" and run["state"] == "returned":
            # Preserve the same launch semantics for runs recorded by older agents.
            run.setdefault("result", {}).setdefault("activityLaunch", "unverified")
        return run

    def _save_result(self, run):
        self.version += 1
        try:
            self.db.save_sender_run(run["id"], run)
            self.unsaved.pop(run["id"], None)
        except Exception as error:
            self.unsaved[run["id"]] = copy.deepcopy(run)
            self.error = f"Result not saved: {error}"

    async def activity_context(self, token):
        self.require_token(token)
        endpoint = self.session
        if endpoint is None or not endpoint.is_ready():
            raise SenderError("Sender is disconnected")
        try:
            context = await asyncio.wait_for(sender_io(endpoint.activity_context), timeout=2)
        except Exception:
            context = {"state": "unknown"}
        self.require_token(token)
        return {"package": self.identity["package"], **context}

    def retry_save(self):
        for run in list(self.unsaved.values()):
            self._save_result(run)
        if not self.unsaved:
            self.error = None

    def execute(self, request_id, revision, token, execution_key):
        self.require_token(token)
        if not isinstance(execution_key, str) or not 1 <= len(execution_key) <= 128:
            raise SenderError("An execution key of 1–128 characters is required")
        previous = self.db.sender_run(execution_key=execution_key)
        if previous is not None:
            if previous["request_id"] != request_id or previous["revision"] != revision:
                raise SenderError("Execution key already belongs to another request revision")
            return self.get_run(previous["id"])
        if self.active_run is not None or self.session is None or not self.session.is_ready():
            raise SenderError("Sender is busy or disconnected")
        saved = self.get_request(request_id)
        if revision != saved["revision"]:
            raise SenderError("Request changed; reload it before sending")
        request = validate_request(saved["request"])
        run = dict(request_id=request_id, revision=revision, name=saved["name"], request=request,
                   sender=copy.deepcopy(self.identity), device=self.session.device_id,
                   state="preparing", createdAt=now())
        # No dispatch is allowed before the immutable snapshot is durably written.
        run["id"] = self.db.create_sender_run(execution_key, run)
        run["execution_key"] = execution_key
        self.version += 1
        self.active_run = run["id"]
        loop = asyncio.get_running_loop()
        def started(job_id, started_at, identity=None):
            try:
                loop.call_soon_threadsafe(self._started, token, run["id"], job_id, started_at, identity)
            except RuntimeError:
                pass
        self.session.started_cb = started
        self.task = asyncio.create_task(self._execute(self.session, token, run))
        return copy.deepcopy(run)

    def _started(self, token, run_id, job_id, started_at, identity=None):
        if token != self.token or run_id != self.active_run:
            return
        run = self.get_run(run_id)
        if job_id != run["execution_key"]:
            return
        run.update(state="running", startedAt=started_at)
        if identity is not None:
            run["sender"] = copy.deepcopy(identity)
        self._save_result(run)

    async def cancel(self, run_id, token):
        self.require_token(token)
        if run_id != self.active_run or not self.session:
            raise SenderError("This run is not active")
        run = self.get_run(run_id)
        if run["request"]["operation"] not in ("query", "openFileDescriptor"):
            raise SenderError("This operation cannot be cancelled")
        accepted = await sender_io(self.session.cancel, run["execution_key"])
        if accepted and token == self.token and self.active_run == run_id:
            run = self.get_run(run_id)
            run["cancellationRequested"] = True
            self._save_result(run)
        return self.get_run(run_id)

    async def _execute(self, endpoint, token, run):
        if token != self.token or run["id"] != self.active_run:
            return
        try:
            result = await sender_io(endpoint.execute, copy.deepcopy(run["request"]), run["execution_key"])
            run.update(result)
        except Exception as error:
            run.update(state="unknown", error=str(error))
        run["receivedAt"] = now()
        if token == self.token:
            previous = self.get_run(run["id"])
            if previous.get("cancellationRequested"):
                run["cancellationRequested"] = True
            self._save_result(run)
            self.active_run = None

    async def wait(self, run_id, timeout=30):
        if not 0 <= timeout <= 30:
            raise SenderError("Wait timeout must be between 0 and 30 seconds")
        if run_id == self.active_run and self.task:
            try:
                await asyncio.wait_for(asyncio.shield(self.task), timeout)
            except TimeoutError:
                pass
        return self.get_run(run_id)


def endpoint_for_app(app, device_id, pid):
    """Choose one agent per process, retaining the Home discovery context."""
    from noxen.sender_session import SenderSession
    if type(pid) is not int or pid < 1:
        raise SenderError("Select a running application with a valid PID")
    devices = app._home_devices
    if not any(device.id == device_id for device in devices):
        raise SenderError("Select a device discovered in Home")
    observer = app.frida_session
    if app._connection_state == "connecting":
        raise SenderError("Wait for the observer connection to finish")
    if observer and observer.is_ready():
        if app._session_device_id != device_id:
            raise SenderError("Sender and observer must use the same device")
        if getattr(observer._session, "pid", None) != pid:
            observer = None
    else:
        observer = None
    resolver = getattr(devices, "get_device", None)
    if resolver is None:
        raise SenderError("Refresh devices in Home before connecting Sender")
    return SenderSession(device_id, pid, resolver, observer)
