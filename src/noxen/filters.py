import threading
import fnmatch
import copy

from tabulate import tabulate


class FilterManager:
    VALID_TYPES = {"ignore", "focus"}
    VALID_KEYS = {"class", "method", "action", "data", "flags", "category", "component"}

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
            self._filter_list = [
                normalized
                for item in list(filters or [])
                if (normalized := self._normalize_saved_filter(item)) is not None
            ]
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
        if f_type not in cls.VALID_TYPES or not isinstance(rule, dict):
            return None
        if any(key not in cls.VALID_KEYS or not isinstance(value, str) for key, value in rule.items()):
            return None
        return {
            "id": fid,
            "type": f_type,
            "rule": copy.deepcopy(rule),
            "enabled": bool(item.get("enabled", True)),
        }

    def add(self, f_type, rule_parts) -> str:
        if f_type not in self.VALID_TYPES:
            return f"[red]Unknown filter type: {f_type}[/red]"
        valid, rule = self._parse_rule_string(rule_parts)
        if not valid or not rule:
            return "[red]Invalid format — expected key=value[/red]"
        invalid_keys = [k for k in rule if k not in self.VALID_KEYS]
        if invalid_keys:
            return f"[red]Unknown key(s): {', '.join(invalid_keys)} — valid: {', '.join(sorted(self.VALID_KEYS))}[/red]"
        with self._lock:
            for f in self._filter_list:
                if f['type'] == f_type and f['rule'] == rule:
                    return f"[yellow]Already exists as filter #{f['id']}[/yellow]"
            self._filter_list.append({'id': self._id_counter, 'type': f_type, 'rule': rule, 'enabled': True})
            msg = f"[#26a368]Added {f_type} filter #{self._id_counter}: {rule}[/#26a368]"
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
