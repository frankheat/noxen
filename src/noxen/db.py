import copy
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

_MIGRATED_INTENT_COLUMNS = {
    "outcome": "TEXT",
    "original_intent": "TEXT",
    "attack_surface": "TEXT",
}


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
        if self._conn is None:
            return
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO project_info (key, value) VALUES (?, ?)",
                (key, value),
            )
            self._conn.commit()

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

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
            CREATE TABLE IF NOT EXISTS intents (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp            TEXT    NOT NULL,
                class                TEXT,
                method               TEXT,
                action               TEXT,
                component            TEXT,
                data                 TEXT,
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
            entries.append({
                "id": row_id,
                "timestamp": row["timestamp"],
                "class": row["class"],
                "method": row["method"],
                "intent": {
                    "action": row["action"],
                    "component": row["component"],
                    "data": row["data"],
                    "flags": int(raw_flags) if (raw_flags := row["flags"]) else None,
                    "categories": self._load_json_field(row_id, "categories", row["categories"], [], list),
                    "extras": self._load_json_field(row_id, "extras", row["extras"], {}, dict),
                },
                "stackTrace": self._load_json_field(row_id, "stack_trace", row["stack_trace"], [], list),
                "pendingIntentFlags": row["pending_intent_flags"],
                "outcome": row["outcome"],
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

    def _load_json_field(self, row_id: int, field: str, raw_value, default, expected_type: type):
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
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO intents
                   (timestamp, class, method, action, component, data, flags,
                    categories, extras, stack_trace, pending_intent_flags, attack_surface)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    entry.get("timestamp"),
                    entry.get("class"),
                    entry.get("method"),
                    info.get("action"),
                    info.get("component"),
                    info.get("data"),
                    info.get("flags") or None,
                    json.dumps(info.get("categories") or []),
                    json.dumps(info.get("extras") or {}),
                    json.dumps(entry.get("stackTrace") or []),
                    entry.get("pendingIntentFlags"),
                    json.dumps(entry.get("attackSurface")) if entry.get("attackSurface") else None,
                ),
            )
            self._conn.commit()
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

    def save_history_filters(self, filters: list) -> None:
        """Persist the history filter list to project_info."""
        self.set_info("history_filters", json.dumps(filters))

    def load_history_filters(self) -> list:
        """Return the saved history filter list, or [] if none."""
        return self._load_json_info("history_filters", [], list)

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
            return
        with self._lock:
            self._conn.execute("DELETE FROM intents")
            self._conn.commit()

    def update_modified_intent(self, intent_id: int, original_info: dict, modified_info: dict) -> None:
        """Persist the modified intent fields and the original snapshot."""
        if self._conn is None or intent_id is None:
            return
        with self._lock:
            self._conn.execute(
                """UPDATE intents SET
                   action=?, data=?, flags=?, categories=?, extras=?, original_intent=?
                   WHERE id=?""",
                (
                    modified_info.get("action"),
                    modified_info.get("data"),
                    modified_info.get("flags") or None,
                    json.dumps(modified_info.get("categories") or []),
                    json.dumps(modified_info.get("extras") or {}),
                    json.dumps(original_info),
                    intent_id,
                ),
            )
            self._conn.commit()

    def update_outcome(self, intent_id: int, outcome: str) -> None:
        """Set the outcome ('forwarded' or 'dropped') for a stored intent."""
        if self._conn is None or intent_id is None:
            return
        with self._lock:
            self._conn.execute(
                "UPDATE intents SET outcome=? WHERE id=?",
                (outcome, intent_id),
            )
            self._conn.commit()

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
