"""A Sender endpoint borrows the observer agent or owns a separate attachment."""

from noxen.agent_loader import load_sender_script
from noxen.sender import SenderError


class SenderSession:
    def __init__(self, device_id, pid, resolver, observer=None):
        self.device_id = device_id
        self.pid = pid
        self.resolver = resolver  # Retain the DeviceScan throughout the attachment.
        self.observer = observer
        self.session = None
        self.script = None
        self.detached = False
        self.started_cb = None
        self.detached_cb = None
        self._listening = False

    def connect(self, expected_package):
        try:
            if self.observer is not None:
                if not self.observer.is_ready():
                    raise SenderError("Observer agent is not ready")
                self.script = self.observer._script
            else:
                device = self.resolver(self.device_id, timeout=5)
                self.session = device.attach(self.pid)
                self.session.on("detached", self._detached)
                self.script = self.session.create_script(load_sender_script())
                self.script.load()
            self.script.on("message", self._message)
            self._listening = True
            if self.observer is not None:
                self.script.on("destroyed", self._observer_destroyed)
            identity = self.script.exports_sync.sender_identity()
            if identity["pid"] != self.pid or identity["package"] != expected_package:
                raise SenderError("Sender identity changed; select the app again")
            if not self.is_ready():
                raise SenderError("Sender disconnected during initialization")
            return identity
        except BaseException:
            self.close()
            raise

    def _detached(self, reason, crash=None):
        was_detached = self.detached
        self.detached = True
        if not was_detached and self.detached_cb:
            self.detached_cb(reason, crash)

    def _observer_destroyed(self):
        self._detached("observer-agent-destroyed")

    def _message(self, message, data):
        payload = message.get("payload")
        if message.get("type") == "send" and isinstance(payload, dict) and payload.get("noxenEvent") == "sender_started":
            if self.started_cb:
                self.started_cb(payload.get("jobId"), payload.get("startedAt"), payload.get("sender"))

    def is_ready(self):
        if self.detached or self.script is None:
            return False
        return self.observer is None or (self.observer.is_ready() and self.observer._script is self.script)

    def execute(self, request, job_id):
        if not self.is_ready():
            raise SenderError("Sender is disconnected")
        return self.script.exports_sync.sender_execute(request, job_id)

    def activity_context(self):
        if not self.is_ready():
            raise SenderError("Sender is disconnected")
        return self.script.exports_sync.sender_activity_context()

    def cancel(self, job_id):
        if not self.is_ready():
            raise SenderError("Sender is disconnected")
        return self.script.exports_sync.sender_cancel(job_id)

    def close(self):
        self.detached = True
        if self._listening and self.script:
            try:
                self.script.off("message", self._message)
            except Exception:
                pass  # The script may already have been destroyed by a detach.
            if self.observer is not None:
                try:
                    self.script.off("destroyed", self._observer_destroyed)
                except Exception:
                    pass
            self._listening = False
        if self.session is not None:
            try:
                self.session.detach()
            finally:
                self.session = None
        self.script = None
