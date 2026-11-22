import threading
import fnmatch
import copy
import os
from urllib.parse import urlsplit

from tabulate import tabulate


FILTER_CHOICES = {"event": ("intent", "provider"), "direction": ("incoming", "outgoing")}


def provider_filter_context(record, *, history=False):
    arguments = record.get("arguments") or {}
    uri = str(arguments.get("uri") or "")
    authority = str(arguments.get("authority") or "")
    if not authority and uri:
        try:
            authority = urlsplit(uri).netloc
        except ValueError:
            pass
    if "@" in authority and authority.split("@", 1)[0].isdigit():
        authority = authority.split("@", 1)[1]
    legacy_args = (record.get("sentArguments") or arguments) if history else arguments
    result = {
        "event": "provider",
        "class": str(record.get("class") or ""),
        "method": str(record.get("method") or ""),
        "uri": uri,
        "authority": str(authority),
        "data": str(legacy_args.get("uri") or ""),
        "flags": "0" if history else "",
        "category": [],
    }
    if history:
        result.update(action="", component="")
    if record.get("direction") in FILTER_CHOICES["direction"]:
        result["direction"] = record["direction"]
    return result


class FilterManager:
    VALID_TYPES = {"ignore", "focus"}
    VALID_KEYS = {"class", "method", "action", "data", "flags", "category", "component",
                  "event", "direction", "authority", "uri"}

    def __init__(self):
        self._filter_list = []
        self._id_counter = 1
        self._lock = threading.Lock()

    @classmethod
    def from_saved(cls, filters):
        manager = cls()
        manager.replace_all(filters or [])
        return manager

    def replace_all(self, filters):
        with self._lock:
            self._filter_list = []
            seen = set()
            for item in filters or ():
                normalized = self._normalize_saved_filter(item)
                if normalized is not None and normalized["id"] not in seen:
                    seen.add(normalized["id"])
                    self._filter_list.append(normalized)
            self._id_counter = max((f.get("id", 0) for f in self._filter_list), default=0) + 1

    def export(self):
        with self._lock:
            return copy.deepcopy(self._filter_list)

    @staticmethod
    def _parse_rule_string(parts):
        rule = {}
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                rule[k] = v
            else:
                return False, {}
        return True, rule

    @classmethod
    def _normalize_saved_filter(cls, item):
        if not isinstance(item, dict):
            return None
        try:
            fid = int(item["id"])
        except (KeyError, TypeError, ValueError):
            return None
        f_type = item.get("type")
        rule = item.get("rule")
        if (fid <= 0 or isinstance(item["id"], bool) or not isinstance(f_type, str)
                or f_type not in cls.VALID_TYPES or not isinstance(rule, dict) or not rule):
            return None
        if any(key not in cls.VALID_KEYS or not isinstance(value, str)
               or (key in FILTER_CHOICES and value not in FILTER_CHOICES[key]) for key, value in rule.items()):
            return None
        return {
            "id": fid,
            "type": f_type,
            "rule": copy.deepcopy(rule),
            "enabled": bool(item.get("enabled", True)),
        }

    def add(self, f_type, rule_parts, *, enabled=True) -> str:
        if f_type not in self.VALID_TYPES:
            return f"[red]Unknown filter type: {f_type}[/red]"
        valid, rule = self._parse_rule_string(rule_parts)
        if not valid or not rule:
            return "[red]Invalid format — expected key=value[/red]"
        invalid_keys = [k for k in rule if k not in self.VALID_KEYS]
        if invalid_keys:
            return f"[red]Unknown key(s): {', '.join(invalid_keys)} — valid: {', '.join(sorted(self.VALID_KEYS))}[/red]"
        if any(key in rule and rule[key] not in choices for key, choices in FILTER_CHOICES.items()):
            return "[red]Select a valid event and direction.[/red]"
        with self._lock:
            for f in self._filter_list:
                if f['type'] == f_type and f['rule'] == rule:
                    return f"[yellow]Already exists as filter #{f['id']}[/yellow]"
            self._filter_list.append({'id': self._id_counter, 'type': f_type, 'rule': rule, 'enabled': enabled})
            msg = f"[#26a368]Added {f_type} filter #{self._id_counter}[/#26a368]"
            self._id_counter += 1
        return msg

    def remove(self, fid) -> str:
        with self._lock:
            before = len(self._filter_list)
            self._filter_list = [f for f in self._filter_list if str(f['id']) != str(fid)]
            removed = len(self._filter_list) < before
        if removed:
            return f"[#26a368]Filter #{fid} removed[/#26a368]"
        return f"[red]No filter with id #{fid}[/red]"

    def toggle(self, fid) -> str:
        with self._lock:
            for f in self._filter_list:
                if str(f['id']) == str(fid):
                    f['enabled'] = not f.get('enabled', True)
                    state = "enabled" if f['enabled'] else "disabled"
                    return f"[#26a368]Filter #{fid} {state}[/#26a368]"
        return f"[red]No filter with id #{fid}[/red]"

    def get_active(self) -> tuple:
        with self._lock:
            ignore_list = [copy.deepcopy(f['rule']) for f in self._filter_list if f['type'] == 'ignore' and f.get('enabled', True)]
            focus_list = [copy.deepcopy(f['rule']) for f in self._filter_list if f['type'] == 'focus' and f.get('enabled', True)]
        return ignore_list, focus_list

    def agent_rules(self):
        """Use the host matcher for legacy shell classes and platform-specific globs."""
        ignore, focus = self.get_active()
        relevant = focus or ignore
        if (os.name == "nt" or len(relevant) > 128
                or any("[" in pattern or len(pattern) > 256 for rule in relevant for pattern in rule.values())):
            return None
        return {"focus": bool(focus), "rules": relevant}

    def edit(self, fid, f_type, rule_parts):
        ok, rule = self._parse_rule_string(rule_parts)
        with self._lock:
            candidate = next((item for item in self._filter_list if item["id"] == fid), None)
            if candidate is None:
                return "[red]Filter no longer exists.[/red]"
            replacement = {**candidate, "type": f_type, "rule": rule}
            if not ok or not rule or self._normalize_saved_filter(replacement) is None:
                return "[red]Invalid filter conditions.[/red]"
            if any(item["id"] != fid and item["type"] == f_type and item["rule"] == rule
                   for item in self._filter_list):
                return "[yellow]A filter with these conditions already exists.[/yellow]"
            candidate.update(replacement)
            return ""
    def is_visible(self, context: dict) -> bool:
        ignore_list, focus_list = self.get_active()
        if focus_list:
            return self.check_match(context, focus_list)
        return not self.check_match(context, ignore_list)

    def format(self) -> str:
        with self._lock:
            if not self._filter_list:
                return "[dim]No active filters[/dim]"
            rows = []
            for f in self._filter_list:
                rule_str = " ".join([f"{k}={v}" for k, v in f['rule'].items()])
                rows.append([f['id'], f['type'].upper(), rule_str])
        return tabulate(rows, headers=["ID", "Type", "Rule"], tablefmt="simple")

    @staticmethod
    def check_match(context, filters) -> bool:
        for rule in filters:
            matches = True
            for k, p in rule.items():
                if k not in context:
                    matches = False
                    break
                val = context[k]
                is_presence_check = (
                    p in ("set", "unset") or
                    (k == "component" and p in ("explicit", "implicit"))
                )
                if is_presence_check:
                    is_set = bool(val) if not isinstance(val, list) else len(val) > 0
                    want_set = p in ("set", "explicit")
                    if is_set != want_set:
                        matches = False
                        break
                elif isinstance(val, list):
                    if not any(fnmatch.fnmatch(v, p) for v in val):
                        matches = False
                        break
                elif not fnmatch.fnmatch(val, p):
                    matches = False
                    break
            if matches:
                return True
        return False
