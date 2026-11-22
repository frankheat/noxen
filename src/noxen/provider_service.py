"""Provider request decisions and durable records shared by TUI and MCP."""

import copy
import queue
from uuid import uuid4

from noxen.sender_service import sender_io


class ProviderService:
    def __init__(self, db, changed=None):
        self.db = db
        self.changed = changed
        self.history_ids = {}
        self.session = None
        self.connection = uuid4().hex
        self.inbox = queue.Queue(maxsize=512)
        self.control_inbox = queue.SimpleQueue()
        self._control_id = None
        self.lost = 0
        self.enabled = {"outgoing": False, "incoming": False}
        self.hooks = []
        self.records = {}
        self.held = None
        self.version = 0
        self.error = None
        self.unsaved = {}
        self.busy = False
        self.db.interrupt_provider_calls()

    def bind(self, session):
        if session is self.session:
            return
        if self.held is not None:
            record = self.records[self.held]
            record["state"] = "unknown"
            record["error"] = "Connection ended while this request was held."
            self.persist(record)
        self.held = None
        self.session = session
        self.connection = uuid4().hex
        self.enabled = {"outgoing": False, "incoming": False}
        self.hooks = []
        self.records = {}
        self.version += 1
        if session is not None:
            connection = self.connection
            session.provider_cb = lambda event: self.receive(connection, event)

    def receive(self, connection, event):
        if connection != self.connection:
            return
        # A held request must remain controllable even if the app floods events.
        # At most one hold is active and each resolution drains this inbox first.
        if event.get("decisionId"):
            self._control_id = event["id"]
        if event.get("id") == self._control_id:
            self.control_inbox.put((connection, event))
            if event.get("noxenEvent") == "provider_result":
                self._control_id = None
        else:
            try:
                self.inbox.put_nowait((connection, event))
            except queue.Full:
                self.lost += 1

    def persist(self, record):
        key = (self.connection, record["id"])
        try:
            history_id = self.db.save_provider_call(self.connection, record["id"], record)
            self.history_ids[key] = history_id
            self.unsaved.pop(key, None)
            if not self.unsaved:
                self.error = None
        except Exception as error:
            if key in self.unsaved or len(self.unsaved) < 512:
                self.unsaved[key] = copy.deepcopy(record)
            else:
                self.lost += 1
            self.error = f"Provider call could not be saved: {error}"
        self.version += 1
        if self.changed:
            self.changed(record, self.connection, self.history_ids.get(key), self.error)

    def drain(self):
        while not self.control_inbox.empty():
            self.consume(*self.control_inbox.get())
        for _ in range(32):
            if self.inbox.empty():
                break
            self.consume(*self.inbox.get())
        self.trim()

    def retry_save(self):
        saved = False
        for (connection, id_), record in list(self.unsaved.items())[:32]:
            try:
                history_id = self.db.save_provider_call(connection, id_, record)
                self.history_ids[connection, id_] = history_id
                if self.changed:
                    self.changed(record, connection, history_id, None)
            except Exception:
                return
            del self.unsaved[connection, id_]
            saved = True
        if saved:
            self.version += 1
        if not self.unsaved:
            self.error = None

    def consume(self, connection, event):
        if connection != self.connection or not isinstance(event.get("id"), str):
            return
        id_ = event["id"]
        if event.get("noxenEvent") == "provider_request":
            record = copy.deepcopy(event)
            record["target"] = self.session._config.target_label()
            self.records[id_] = record
            if record["state"] == "held":
                self.held = id_
        else:
            record = self.records.get(id_)
            if record is None:
                return
            if event.get("noxenEvent") == "provider_update":
                field = "responseDecision" if event.get("phase") == "response" else "requestDecision"
                record[field] = event["state"]
                record["decision"] = "modified_forwarded" if "modified_forwarded" in (record.get("requestDecision"), record.get("responseDecision")) else event["state"]
            update = copy.deepcopy(event)
            if event.get("noxenEvent") == "provider_response" and "time" in update:
                update["responseAt"] = update.pop("time")
                update["responseCaptureSequence"] = update.pop("captureSequence", None)
            if event.get("noxenEvent") == "provider_result":
                update["finishedAt"] = update.pop("time", None)
                update["resultCaptureSequence"] = update.pop("captureSequence", None)
            record.update(update)
            if record["state"] == "held":
                self.held = id_
            elif id_ == self.held:
                self.held = None
        self.persist(record)

    def trim(self):
        # Completed records stay on disk; retain only a bounded live snapshot.
        if len(self.records) > 256:
            for id_ in list(self.records):
                if len(self.records) <= 256:
                    break
                if id_ != self.held and self.records[id_]["state"] in ("returned", "exception", "dropped"):
                    del self.records[id_]

    def status(self):
        self.drain()
        return {"connection": self.connection, "enabled": dict(self.enabled),
                "held": copy.deepcopy(self.records.get(self.held)), "hooks": copy.deepcopy(self.hooks),
                "busy": self.busy, "error": self.error, "lost_events": self.lost}

    async def resolve(self, connection, decision_id, action, arguments=None):
        self.drain()
        if connection != self.connection or decision_id != (self.records.get(self.held) or {}).get("decisionId") or self.session is None:
            raise ValueError("Provider hold changed; read the current request again")
        if action not in ("forward", "drop", "inspect"):
            raise ValueError("Choose forward, drop or inspect")
        if self.busy:
            raise ValueError("Wait for the current provider operation")
        if arguments is not None and len(str(arguments)) > 65536:
            raise ValueError("Provider arguments exceed 64 KiB")
        self.busy = True
        try:
            accepted = await sender_io(self.session._script.exports_sync.resolve_provider,
                                       decision_id, action, arguments)
            if not accepted:
                raise ValueError("Provider hold changed; read the current request again")
            self.drain()
            return {"accepted": True}
        finally:
            self.busy = False
