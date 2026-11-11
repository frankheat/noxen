import copy
import json
import os
import sqlite3
import threading
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from noxen.history_columns import normalize_history_column_widths
from noxen.monitor import event_sort_value

_MIGRATED_INTENT_COLUMNS = {
    "outcome": "TEXT",
    "original_intent": "TEXT",
    "attack_surface": "TEXT",
    "mime_type": "TEXT",
    "selector": "TEXT",
    "clip_data": "TEXT",
    "modification_error": "TEXT",
    "intent_package": "TEXT",
    "capture_metadata": "TEXT",
}

_CAPTURE_METADATA_KEYS = (
    "extrasMeta", "categoriesTruncated", "categoriesReadError",
    "errors", "unreadableFields", "truncatedFields",
)


def _stored_capture_metadata(info: dict):
    """Persist capture completeness and lossless field-encoding metadata."""
    metadata = {key: info[key] for key in _CAPTURE_METADATA_KEYS if key in info}
    # Keep the legacy MIME column convention (empty = observed null). Only new
    # captures of a real empty string need this marker; old rows stay unchanged.
    if info.get("mimeType") == "":
        metadata["emptyMimeType"] = True
    return json.dumps(metadata) if metadata else None


def _stored_mime_type(info: dict):
    """Distinguish an uncaptured field (NULL) from a captured absent type (empty)."""
    return (info.get("mimeType") or "") if "mimeType" in info else None


def _stored_selector(info: dict):
    """Distinguish legacy captures from a captured absent/present selector."""
    return json.dumps(info.get("selector")) if "selector" in info else None


def _stored_clip_data(info: dict):
    """Preserve the distinction between old captures and an absent ClipData."""
    return json.dumps(info.get("clipData")) if "clipData" in info else None


def _stored_package(info: dict):
    """SQL NULL means uncaptured; JSON preserves null and exact package strings."""
    return json.dumps(info.get("package")) if "package" in info else None


class ProjectDB:
    def __init__(self, path: str):
        self._path = path
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()
        self.load_warnings: list[str] = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def create(self, name: str) -> None:
        """Create a new project DB. Raises FileExistsError if path already exists."""
        if os.path.exists(self._path):
            raise FileExistsError(
                f"Project file already exists: {self._path}\n"
                "Use --project to open it."
            )
        self._connect()
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.executemany(
                "INSERT OR REPLACE INTO project_info (key, value) VALUES (?, ?)",
                [("name", name), ("created_at", now)],
            )
            self._conn.commit()

    def open_existing(self) -> list[dict]:
        """Open an existing project DB and return all stored intents.
        Raises FileNotFoundError if path does not exist."""
        if not os.path.exists(self._path):
            raise FileNotFoundError(f"Project not found: {self._path}")
        self._connect()
        self.load_warnings = []
        return self._load_all()

    def set_info(self, key: str, value: str) -> None:
        """Store or update a metadata key in project_info."""
        with self._lock:
            if self._conn is None:
                return
            with self._conn as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO project_info (key, value) VALUES (?, ?)",
                    (key, value),
                )

    def get_info(self, key: str, default: str = "") -> str:
        """Return a metadata value from project_info."""
        with self._lock:
            if self._conn is None:
                return default
            row = self._conn.execute(
                "SELECT value FROM project_info WHERE key=?",
                (key,),
            ).fetchone()
        if not row or row[0] is None:
            return default
        return str(row[0])

    def close(self) -> None:
        with self._lock:
            if self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None

    def save_monitor_batch(self, recording, started, events, lost, unsaved, status):
        payloads = [json.dumps(event, separators=(",", ":")) for event in events]
        with self._lock, self._require_connection() as conn:
            size = sum(map(len, payloads))
            conn.execute("""
                INSERT INTO monitor_recordings (id, started, lost, unsaved, status, bytes)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET lost=excluded.lost, unsaved=excluded.unsaved,
                    status=excluded.status, bytes=monitor_recordings.bytes+excluded.bytes
            """, (recording, started, lost, unsaved, status, size))
            conn.executemany(
                "INSERT INTO monitor_events (recording, payload) VALUES (?, ?)",
                ((recording, payload) for payload in payloads),
            )

    def monitor_event_summary(self):
        with self._lock:
            conn = self._require_connection()
            return conn.execute("""
                SELECT COALESCE(SUM(lost), 0), COALESCE(SUM(unsaved), 0),
                       COALESCE(SUM(status != 'complete'), 0)
                FROM monitor_recordings
            """).fetchone()

    def monitor_event_page(self, query, before, limit, cancelled=None, *, sort=None):
        column, reverse = sort or ("id", True)
        direction = "DESC" if reverse else "ASC"
        comparison = "<" if reverse else ">"
        sort_key = "id" if column == "id" else "monitor_sort_key(payload)"
        order_by = f"sort_key {direction}"
        if column != "id":
            order_by += f", id {direction}"
        conditions, params = [], []
        if before is not None:
            if column == "id":
                conditions.append(f"id {comparison} ?")
                params.append(before[1] if sort else before)
            else:
                conditions.append(f"({sort_key}, id) {comparison} (?, ?)")
                params.extend(before)
        if query:
            conditions.append("instr(lower(payload), ?) > 0")
            params.append(query)
        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        # Search can scan the project. Use a separate read-only connection so
        # SQLite's WAL lets capture continue while a page is being read.
        uri = Path(self._path).resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as conn:
            if cancelled is not None:
                conn.set_progress_handler(cancelled, 1000)
            conn.execute("BEGIN")
            latest_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM monitor_events").fetchone()[0]
            if column != "id":
                conn.create_function(
                    "monitor_sort_key", 1,
                    lambda payload: event_sort_value(json.loads(payload), column),
                    deterministic=True,
                )
            rows = conn.execute(
                f"""SELECT id, recording, payload, {sort_key} AS sort_key
                    FROM monitor_events {where} ORDER BY {order_by} LIMIT ?""",
                (*params, limit + 1),
            ).fetchall()
        page = rows[:limit]
        if sort is None:
            page.reverse()
        events = [dict(json.loads(payload), _db_id=row_id, _recording=recording, _sort_key=value)
                  for row_id, recording, payload, value in page]
        return events, len(rows) > limit, latest_id

    def clear_monitor_events(self):
        with self._lock, self._require_connection() as conn:
            conn.execute("DELETE FROM monitor_recordings")

    def _require_connection(self):
        if self._conn is None:
            raise sqlite3.ProgrammingError("Project database is closed")
        return self._conn

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _connect(self) -> None:
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._create_tables()
        self._migrate()

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS project_info (
                key   TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS monitor_recordings (
                id TEXT PRIMARY KEY,
                started TEXT NOT NULL,
                lost INTEGER NOT NULL,
                unsaved INTEGER NOT NULL,
                status TEXT NOT NULL,
                bytes INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS monitor_events (
                id INTEGER PRIMARY KEY,
                recording TEXT NOT NULL REFERENCES monitor_recordings(id) ON DELETE CASCADE,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS monitor_events_recording ON monitor_events(recording, id);
            CREATE TABLE IF NOT EXISTS intents (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp            TEXT    NOT NULL,
                class                TEXT,
                method               TEXT,
                action               TEXT,
                component            TEXT,
                data                 TEXT,
                mime_type            TEXT,
                selector             TEXT,
                clip_data            TEXT,
                intent_package       TEXT,
                flags                INTEGER,
                categories           TEXT,
                extras               TEXT,
                stack_trace          TEXT,
                pending_intent_flags INTEGER,
                outcome              TEXT CHECK (outcome IN ('forwarded', 'dropped', 'modified_forwarded'))
            );
        """)
        self._conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after the initial schema, if missing."""
        existing = self._table_columns("intents")
        for name, definition in _MIGRATED_INTENT_COLUMNS.items():
            if name not in existing:
                self._conn.execute(f"ALTER TABLE intents ADD COLUMN {name} {definition}")
        self._conn.commit()

    def _table_columns(self, table_name: str) -> set[str]:
        rows = self._conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {row[1] for row in rows}

    def _load_all(self) -> list[dict]:
        self._conn.row_factory = sqlite3.Row
        rows = self._conn.execute("SELECT * FROM intents ORDER BY id").fetchall()
        self._conn.row_factory = None
        entries = []
        for row in rows:
            row_id = row["id"]
            intent = {
                "action": row["action"],
                "component": row["component"],
                "data": row["data"],
                "flags": int(raw_flags) if (raw_flags := row["flags"]) is not None else None,
                "categories": self._load_json_field(row_id, "categories", row["categories"], [], list),
                "extras": self._load_json_field(row_id, "extras", row["extras"], {}, dict),
            }
            # NULL identifies captures made before MIME type recording. An empty string
            # means an observed absent type unless emptyMimeType below marks a real
            # empty string. Rows without that marker retain their legacy meaning.
            if row["mime_type"] is not None:
                intent["mimeType"] = row["mime_type"] or None
            if row["intent_package"] is not None:
                intent["package"] = self._load_json_field(
                    row_id, "intent_package", row["intent_package"], None, (str, type(None))
                )
            # SQL NULL means the capture predates selector recording. JSON null means
            # the selector was inspected and absent; an object is the captured tree.
            if row["selector"] is not None:
                intent["selector"] = self._load_json_field(
                    row_id,
                    "selector",
                    row["selector"],
                    None,
                    (dict, type(None)),
                )
            if row["clip_data"] is not None:
                intent["clipData"] = self._load_json_field(
                    row_id, "clip_data", row["clip_data"], None, (dict, type(None))
                )
            if row["capture_metadata"] is not None:
                metadata = self._load_json_field(
                    row_id, "capture_metadata", row["capture_metadata"],
                    {"extrasMeta": {"error": "Capture metadata unavailable in project"}}, dict,
                )
                intent.update({key: metadata[key] for key in _CAPTURE_METADATA_KEYS if key in metadata})
                if metadata.get("emptyMimeType") is True and row["mime_type"] == "":
                    intent["mimeType"] = ""
            entries.append({
                "id": row_id,
                "timestamp": row["timestamp"],
                "class": row["class"],
                "method": row["method"],
                "intent": intent,
                "stackTrace": self._load_json_field(row_id, "stack_trace", row["stack_trace"], [], list),
                "pendingIntentFlags": row["pending_intent_flags"],
                "outcome": row["outcome"],
                "modification_error": row["modification_error"],
                "original_intent": self._load_json_field(
                    row_id,
                    "original_intent",
                    row["original_intent"],
                    None,
                    dict,
                ),
                "attackSurface": self._load_json_field(
                    row_id,
                    "attack_surface",
                    row["attack_surface"] if "attack_surface" in row.keys() else None,
                    {},
                    dict,
                ),
            })
        return entries

    def _load_json_field(
        self,
        row_id: int,
        field: str,
        raw_value,
        default,
        expected_type: type | tuple[type, ...],
    ):
        if raw_value in (None, ""):
            return copy.deepcopy(default)
        try:
            value = json.loads(raw_value)
        except (json.JSONDecodeError, TypeError):
            self.load_warnings.append(
                f"Invalid JSON in intents row #{row_id}, field '{field}'. Using a safe default."
            )
            return copy.deepcopy(default)
        if not isinstance(value, expected_type):
            self.load_warnings.append(
                f"Invalid JSON type in intents row #{row_id}, field '{field}'. Using a safe default."
            )
            return copy.deepcopy(default)
        return value

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save_intent(self, entry: dict) -> int:
        """Insert an intent row. Returns the DB-assigned id, or 0 if unavailable."""
        if self._conn is None:
            return 0
        info = entry.get("intent", {}) or {}
        with self._lock, self._conn:
            cur = self._conn.execute(
                """INSERT INTO intents
                   (timestamp, class, method, action, component, data, mime_type, selector, clip_data, flags,
                    categories, extras, stack_trace, pending_intent_flags, attack_surface, intent_package,
                    capture_metadata)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    entry.get("timestamp"),
                    entry.get("class"),
                    entry.get("method"),
                    info.get("action"),
                    info.get("component"),
                    info.get("data"),
                    _stored_mime_type(info),
                    _stored_selector(info),
                    _stored_clip_data(info),
                    info.get("flags"),
                    json.dumps(info.get("categories") or []),
                    json.dumps(info.get("extras") or {}),
                    json.dumps(entry.get("stackTrace") or []),
                    entry.get("pendingIntentFlags"),
                    json.dumps(entry.get("attackSurface")) if entry.get("attackSurface") else None,
                    _stored_package(info),
                    _stored_capture_metadata(info),
                ),
            )
            return cur.lastrowid

    def save_intercept_filters(self, filters: list) -> None:
        """Persist the intercept filter list to project_info."""
        self.set_info("intercept_filters", json.dumps(filters))

    def load_intercept_filters(self) -> list:
        """Return the saved intercept filter list, or [] if none."""
        return self._load_json_info("intercept_filters", [], list)

    def save_history_columns(self, visible: list) -> None:
        """Persist visible history column keys."""
        self.set_info("history_columns", json.dumps(visible))

    def load_history_columns(self) -> list | None:
        """Return saved visible column keys, or None if not set."""
        return self._load_json_info("history_columns", None, list)

    def save_history_column_widths(self, widths: dict) -> None:
        """Persist optional history column widths."""
        self.set_info("history_column_widths", json.dumps(normalize_history_column_widths(widths)))

    def load_history_column_widths(self) -> dict[str, int]:
        """Return saved history column widths, or {} if none."""
        return normalize_history_column_widths(self._load_json_info("history_column_widths", {}, dict))

    def save_monitor_event_columns(self, visible: list[str], widths: dict[str, int]) -> None:
        self.set_info("monitor_event_columns", json.dumps({"visible": visible, "widths": widths}))

    def load_monitor_event_columns(self) -> dict:
        return self._load_json_info("monitor_event_columns", {}, dict)

    def save_history_filters(self, filters: list) -> None:
        """Persist the history filter list to project_info."""
        self.set_info("history_filters", json.dumps(filters))

    def load_history_filters(self) -> list:
        """Return the saved history filter list, or [] if none."""
        return self._load_json_info("history_filters", [], list)

    def save_hook_config_path(self, path: str) -> None:
        """Persist the project-specific custom hook config path."""
        self.set_info("hook_config_path", path)

    def load_hook_config_path(self) -> str:
        """Return the saved project-specific custom hook config path."""
        return self.get_info("hook_config_path")

    def save_extra_script_path(self, path: str) -> None:
        """Persist the project-specific extra script path."""
        self.set_info("extra_script_path", path)

    def load_extra_script_path(self) -> str:
        """Return the saved project-specific extra script path."""
        return self.get_info("extra_script_path")

    def _load_json_info(self, key: str, default, expected_type: type):
        if self._conn is None:
            return default
        row = self._conn.execute(
            "SELECT value FROM project_info WHERE key=?",
            (key,),
        ).fetchone()
        if not row:
            return default
        try:
            value = json.loads(row[0])
        except (json.JSONDecodeError, TypeError):
            return default
        return value if isinstance(value, expected_type) else default

    def clear_intents(self) -> None:
        """Delete all rows from the intents table."""
        if self._conn is None:
            raise RuntimeError("Project database is unavailable")
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM intents")

    def update_modified_intent(self, intent_id: int, original_info: dict, modified_info: dict) -> None:
        """Persist the modified intent fields and the original snapshot."""
        if self._conn is None or intent_id is None:
            return
        with self._lock, self._conn:
            self._conn.execute(
                """UPDATE intents SET
                   action=?, component=?, data=?, mime_type=?, flags=?, categories=?, extras=?, original_intent=?, intent_package=?,
                   capture_metadata=?
                   WHERE id=?""",
                (
                    modified_info.get("action"),
                    modified_info.get("component"),
                    modified_info.get("data"),
                    _stored_mime_type(modified_info),
                    modified_info.get("flags"),
                    json.dumps(modified_info.get("categories") or []),
                    json.dumps(modified_info.get("extras") or {}),
                    json.dumps(original_info),
                    _stored_package(modified_info),
                    _stored_capture_metadata(modified_info),
                    intent_id,
                ),
            )

    def update_capture_metadata(self, intent_id: int, info: dict) -> None:
        """Refresh completeness markers without claiming the Intent was modified."""
        if self._conn is None or intent_id is None:
            return
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE intents SET capture_metadata=? WHERE id=?",
                (_stored_capture_metadata(info), intent_id),
            )

    def update_modification_error(self, intent_id: int, error: str | None) -> None:
        if self._conn is None or intent_id is None:
            return
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE intents SET modification_error=? WHERE id=?", (error, intent_id)
            )

    def update_outcome(self, intent_id: int, outcome: str) -> None:
        """Set the outcome ('forwarded' or 'dropped') for a stored intent."""
        if self._conn is None or intent_id is None:
            return
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE intents SET outcome=? WHERE id=?",
                (outcome, intent_id),
            )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def path(self) -> str:
        return self._path

    @property
    def name(self) -> str | None:
        if self._conn is None:
            return None
        row = self._conn.execute(
            "SELECT value FROM project_info WHERE key='name'"
        ).fetchone()
        return row[0] if row else None
