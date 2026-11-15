# `server/materialize_password_state.py`

Полный читаемый листинг файла. Это сгенерированное представление в UTF-8: BOM снят для отображения, окончания строк представлены как LF. Для запуска и сохранения исходной кодировки используем [оригинал в `code/`](../../code/server/materialize_password_state.py). Исполняемый код в оригинале сохранён побайтно.

**Назначение.** Формируем текущее состояние АРМ и пользователей из archives, проверяем полноту, SID, run_id, свежесть и ошибки, атомарно публикуем alias.

**Применение.** На Linux выполняем: python3 /opt/wazuh-password-audit/materialize_password_state.py --config /etc/wazuh-password-audit/config.json --once. Требуется Python 3.8+; внешние Python-библиотеки не нужны.

**Особенности.** Источник использует data.password_audit_v2; результат имеет плоские поля и document_kind=host/user. К Windows по сети не подключаемся. Дашборд учитывает valid_until и неполные последние снимки.

**Происхождение.** Проверенный исходный комплект.

**Кодировка оригинала:** UTF-8 без BOM. **Объём:** 539 строк.

**SHA256 оригинала:** `9464c77b20d37939a3f8a0960e42834a6738e4f74446dbedbeb24d289df8ca11`.

Для файлов без завершающего переноса строки перед закрывающим ограждением Markdown добавлен только разделительный LF; оригинал и его контрольная сумма остаются прежними.

## Полный код

```python
#!/usr/bin/env python3
"""Build an atomic current-state view from Wazuh password-audit snapshots.

Reads archives and previously published state; never contacts Windows endpoints.
Requires Python 3.8+ and the standard library only. No passwords or account policy
are changed. Credentials stay in an owner-only auth JSON file.
"""
import argparse
import base64
import copy
import datetime as dt
import hashlib
import json
import os
import re
import ssl
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

UTC = dt.timezone.utc
AUDIT = "password_audit_v2"
HOST_LABELS = {
    "ok": "Данные получены", "partial": "Неполные сведения",
    "error": "Ошибка сборщика", "incomplete": "Снимок доставлен не полностью",
    "stale": "Данные устарели", "clock_error": "Ошибка времени",
    "never_reported": "Данные не поступали",
}
ROW_LABELS = {
    "ok": "Порог не превышен", "overdue": "Возраст или срок превышен",
    "disabled": "Учётная запись отключена", "excluded": "Облачный пароль не оценивается",
    "unknown": "Недостаточно сведений", "stale": "Данные устарели",
    "partial": "Неполные сведения", "error": "Ошибка сбора",
    "incomplete": "Неполный снимок", "clock_error": "Ошибка времени",
    "never_reported": "Данные не поступали",
}
BOOL_FIELDS = ("enabled", "never_expires", "expired_reported", "threshold_exceeded",
               "policy_expired_calculated", "internet_identity")
LONG_FIELDS = ("age_seconds", "age_days", "threshold_days")


def timestamp(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        # Wazuh can emit +0800; Python 3.8/3.9 require the colon form +08:00.
        normalized = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", normalized)
        parsed = dt.datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(UTC)
    except (ValueError, TypeError):
        return None


def iso(value):
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.lower() in ("true", "false", "1", "0"):
        return value.lower() in ("true", "1")
    return None


def as_int(value):
    if isinstance(value, bool) or value is None:
        return None
    try:
        result = int(value)
        if isinstance(value, float) and value != result:
            return None
        if isinstance(value, str) and not re.fullmatch(r"[+-]?\d+", value):
            return None
        return result
    except (ValueError, TypeError, OverflowError):
        return None


def audit(source):
    data = source.get("data", {})
    return data.get(AUDIT, {}) if isinstance(data, dict) else {}


def normalize_user(source):
    raw = audit(source)
    row = {}
    for key in ("sid", "username", "collection_status", "exclusion_reason", "read_error"):
        if isinstance(raw.get(key), str):
            row[key] = raw[key]
    for key in BOOL_FIELDS:
        value = as_bool(raw.get(key))
        if value is not None:
            row[key] = value
    for key in LONG_FIELDS:
        value = as_int(raw.get(key))
        if value is not None and value >= 0:
            row[key] = value
    for out_key, source_key in (("observed_at", "observed_at_utc"),):
        value = timestamp(raw.get(source_key))
        if value:
            row[out_key] = iso(value)
    received = timestamp(source.get("timestamp"))
    if received:
        row["received_at"] = iso(received)
    if isinstance(raw.get("run_id"), str):
        row["record_run_id"] = raw["run_id"]
    return row


def classify_row(row, host_state):
    # A retained older row must never stay green after a failed or stale host run.
    if host_state != "ok":
        return host_state if host_state in ROW_LABELS else "unknown"
    if row.get("enabled") is False:
        return "disabled"
    if row.get("collection_status") == "excluded" or row.get("internet_identity") is True:
        return "excluded"
    if row.get("collection_status") != "ok" or not row.get("sid") or row.get("enabled") is not True:
        return "unknown"
    if any(row.get(key) is True for key in ("threshold_exceeded", "expired_reported", "policy_expired_calculated")):
        return "overdue"
    if "threshold_exceeded" not in row or "expired_reported" not in row:
        return "unknown"
    return "ok"


def validate_snapshot(summary_source, user_sources, agent_id):
    """Return structural validity, normalized rows and diagnostic flags."""
    summary = audit(summary_source)
    run_id = summary.get("run_id")
    expected = as_int(summary.get("expected_user_count"))
    emitted = as_int(summary.get("emitted_user_count"))
    diagnostics = []
    rows = []
    seen = set()
    for source in user_sources:
        source_agent = source.get("agent", {}).get("id")
        raw = audit(source)
        if source_agent != agent_id or raw.get("kind") != "user" or raw.get("run_id") != run_id:
            diagnostics.append("wrong_agent_or_run")
            continue
        row = normalize_user(source)
        sid = row.get("sid", "")
        if not re.fullmatch(r"S-\d+(?:-\d+)+", sid):
            diagnostics.append("missing_or_invalid_sid")
            continue
        if sid in seen:
            diagnostics.append("duplicate_sid")
            continue
        seen.add(sid)
        rows.append(row)
    if not isinstance(run_id, str) or not run_id:
        diagnostics.append("missing_run_id")
    if as_bool(summary.get("enumeration_complete")) is not True:
        diagnostics.append("enumeration_incomplete")
    if as_bool(summary.get("identity_complete")) is not True:
        diagnostics.append("identity_incomplete")
    if expected is None or expected < 0 or emitted is None or emitted < 0:
        diagnostics.append("missing_expected_or_emitted_count")
    elif expected != emitted or expected != len(rows) or expected != len(user_sources):
        diagnostics.append("user_count_mismatch")
    return not diagnostics, rows, sorted(set(diagnostics))


def build_documents(inventory, summaries, user_sources_by_agent, previous_users, now,
                    max_age_seconds=7200, future_tolerance_seconds=300, publication_ttl_seconds=300):
    """Pure state transition; exercised by fixture tests without network access."""
    by_inventory = {}
    for item in inventory:
        agent_id = str(item.get("agent_id", ""))
        if not agent_id or agent_id in by_inventory:
            raise ValueError("Expected inventory has an empty or duplicate agent_id")
        by_inventory[agent_id] = item
    all_ids = sorted(set(by_inventory) | set(summaries) | set(previous_users))
    documents = []
    publication_limit = now + dt.timedelta(seconds=publication_ttl_seconds)
    for agent_id in all_ids:
        expected = by_inventory.get(agent_id, {})
        source = summaries.get(agent_id)
        host = {
            "document_kind": "host", "agent_id": agent_id,
            "agent_name": str(expected.get("agent_name", agent_id)),
            "expected": agent_id in by_inventory and expected.get("expected", True) is not False,
            "published_at": iso(now), "valid_until": iso(publication_limit),
            "snapshot_complete": False, "host_state": "never_reported",
        }
        if expected.get("os"):
            host["os"] = str(expected["os"])
        old_rows = {row["sid"]: copy.deepcopy(row) for row in previous_users.get(agent_id, []) if row.get("sid")}
        accepted = False
        normalized_rows = []
        if source:
            meta = source.get("agent", {})
            host["agent_name"] = str(meta.get("name", host["agent_name"]))
            if meta.get("ip"):
                host["agent_ip"] = str(meta["ip"])
            raw = audit(source)
            observed = timestamp(raw.get("observed_at_utc"))
            received = timestamp(source.get("timestamp"))
            complete, normalized_rows, reasons = validate_snapshot(
                source, user_sources_by_agent.get(agent_id, []), agent_id)
            host["snapshot_complete"] = complete
            host["source_run_id"] = str(raw.get("run_id", ""))
            host["collector_status"] = str(raw.get("collection_status", "unknown"))
            host["policy_read_status"] = str(raw.get("policy_read_status", "unknown"))
            host["snapshot_diagnostics"] = ";".join(reasons)
            for key in ("threshold_days", "expected_user_count", "emitted_user_count", "unknown_count",
                        "excluded_count", "policy_max_age_seconds", "known_over_threshold_count"):
                value = as_int(raw.get(key))
                if value is not None and value >= 0:
                    host[key] = value
            for key in ("policy_max_age_unlimited",):
                value = as_bool(raw.get(key))
                if value is not None:
                    host[key] = value
            if observed:
                host["observed_at"] = iso(observed)
            if received:
                host["received_at"] = iso(received)

            # Accept membership replacement only for a complete, successful snapshot.
            # A later collector failure is still authoritative for host health.
            metadata_clear = all(
                row.get("collection_status") in ("ok", "excluded") and isinstance(row.get("enabled"), bool)
                and (row.get("collection_status") == "excluded" or all(
                    isinstance(row.get(key), bool) for key in ("threshold_exceeded", "never_expires", "expired_reported")))
                for row in normalized_rows)
            accepted = complete and metadata_clear and raw.get("collection_status") == "ok"
            if accepted:
                selected = {row["sid"]: row for row in normalized_rows}
                host["accepted_run_id"] = str(raw["run_id"])
            else:
                selected = old_rows
                for row in normalized_rows:
                    if row["sid"] not in selected:
                        selected[row["sid"]] = row
                old_run_ids = {row.get("record_run_id") for row in old_rows.values() if row.get("record_run_id")}
                if len(old_run_ids) == 1:
                    host["accepted_run_id"] = next(iter(old_run_ids))

            if raw.get("collection_status") == "error":
                state = "error"
            elif not complete:
                state = "incomplete"
            elif raw.get("collection_status") != "ok" or not metadata_clear:
                state = "partial"
            else:
                state = "ok"
            if not observed or not received:
                state = "clock_error"
            elif observed > now + dt.timedelta(seconds=future_tolerance_seconds) or received > now + dt.timedelta(seconds=future_tolerance_seconds):
                state = "clock_error"
            elif (now - observed).total_seconds() > max_age_seconds or (now - received).total_seconds() > max_age_seconds:
                state = "stale"
            if observed and received:
                host["valid_until"] = iso(min(publication_limit,
                    observed + dt.timedelta(seconds=max_age_seconds), received + dt.timedelta(seconds=max_age_seconds)))
            host["host_state"] = state
        else:
            selected = old_rows
        state = host["host_state"]
        host["host_state_label"] = HOST_LABELS[state]
        host["retained_user_count"] = len(selected)
        current_rows = []
        for row in selected.values():
            row = copy.deepcopy(row)
            row.update({
                "document_kind": "user", "agent_id": agent_id, "agent_name": host["agent_name"],
                "host_state": state, "published_at": iso(now), "valid_until": host["valid_until"],
                "is_current_snapshot": bool(accepted and state == "ok"),
            })
            if host.get("os"):
                row["os"] = host["os"]
            row["row_state"] = classify_row(row, state)
            row["row_state_label"] = ROW_LABELS[row["row_state"]]
            current_rows.append(row)
        # Exact metrics are emitted only for accepted fresh state; never display zero on failure.
        if accepted and state == "ok":
            eligible = [row for row in current_rows if row.get("enabled") is True and row.get("collection_status") != "excluded"]
            known = [row for row in eligible if isinstance(row.get("threshold_exceeded"), bool)]
            host["user_count"] = len(current_rows)
            host["enabled_count"] = sum(row.get("enabled") is True for row in current_rows)
            host["excluded_count"] = sum(row.get("collection_status") == "excluded" for row in current_rows)
            host["never_expires_count"] = sum(row.get("never_expires") is True for row in eligible)
            if len(known) == len(eligible):
                host["over_threshold_count"] = sum(row["threshold_exceeded"] for row in known)
            host["expired_reported_count"] = sum(row.get("expired_reported") is True for row in eligible)
            if host.get("policy_read_status") == "ok" and all(
                    isinstance(row.get("policy_expired_calculated"), bool) for row in eligible):
                host["policy_expired_count"] = sum(row["policy_expired_calculated"] for row in eligible)
        documents.append(host)
        documents.extend(current_rows)
    return documents


def mappings():
    props = {}
    for key in ("document_kind", "agent_id", "agent_name", "agent_ip", "os", "sid", "username",
                "host_state", "host_state_label", "row_state", "row_state_label", "source_run_id",
                "accepted_run_id", "record_run_id", "collector_status", "collection_status",
                "policy_read_status", "exclusion_reason"):
        props[key] = {"type": "keyword"}
    for key in ("observed_at", "received_at", "published_at", "valid_until"):
        props[key] = {"type": "date", "format": "strict_date_optional_time||epoch_millis"}
    for key in BOOL_FIELDS + ("expected", "snapshot_complete", "is_current_snapshot", "policy_max_age_unlimited"):
        props[key] = {"type": "boolean"}
    for key in LONG_FIELDS + ("expected_user_count", "emitted_user_count", "unknown_count", "excluded_count",
            "policy_max_age_seconds", "known_over_threshold_count", "retained_user_count", "user_count",
            "enabled_count", "never_expires_count", "over_threshold_count", "expired_reported_count", "policy_expired_count"):
        props[key] = {"type": "long"}
    props["read_error"] = {"type": "text"}
    props["snapshot_diagnostics"] = {"type": "keyword"}
    return {"dynamic": "strict", "properties": props}


class IndexerError(RuntimeError):
    pass


def private_json(path):
    path = Path(path)
    if os.name == "posix":
        info = path.stat()
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("Configuration and authentication files must have mode 0600 or stricter")
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


class Indexer:
    def __init__(self, config):
        self.config = config
        parsed = urllib.parse.urlsplit(config["indexer_url"])
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("indexer_url must be HTTPS without embedded credentials or query")
        self.base = config["indexer_url"].rstrip("/")
        auth = private_json(config["auth_file"])
        value = (auth["username"] + ":" + auth["password"]).encode("utf-8")
        self.authorization = "Basic " + base64.b64encode(value).decode("ascii")
        if config.get("allow_insecure_tls") is True:
            self.context = ssl._create_unverified_context()
        else:
            self.context = ssl.create_default_context(cafile=config.get("ca_file") or None)

    def request(self, method, path, data=None, content_type="application/json", allow_404=False):
        if data is not None and not isinstance(data, bytes):
            data = json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
        req = urllib.request.Request(self.base + path, data=data, method=method,
            headers={"Authorization": self.authorization, "Content-Type": content_type})
        try:
            with urllib.request.urlopen(req, timeout=self.config.get("http_timeout_seconds", 30), context=self.context) as response:
                body = response.read()
                return json.loads(body.decode("utf-8")) if body else {}
        except urllib.error.HTTPError as error:
            if allow_404 and error.code == 404:
                return None
            # Do not include response bodies, credential values or request payloads in logs.
            raise IndexerError("Indexer HTTP {} while {} {}".format(error.code, method, path.split("?")[0])) from None
        except urllib.error.URLError:
            raise IndexerError("Indexer connection/TLS failure") from None

    def latest_summaries(self):
        source = urllib.parse.quote(self.config.get("source_indices", "wazuh-archives-*"), safe="*,-_")
        after = None
        found = {}
        while True:
            composite = {"size": 250, "sources": [{"agent": {"terms": {"field": "agent.id"}}}]}
            if after:
                composite["after"] = after
            body = {"size": 0, "query": {"term": {"data." + AUDIT + ".kind": "summary"}},
                "aggs": {"agents": {"composite": composite, "aggs": {"latest": {"top_hits": {
                    "size": 1, "sort": [{"timestamp": "desc"}], "_source": ["agent", "timestamp", "data." + AUDIT]}}}}}}
            result = self.request("POST", "/" + source + "/_search?allow_no_indices=true&ignore_unavailable=true", body)
            bucket = result.get("aggregations", {}).get("agents", {})
            for entry in bucket.get("buckets", []):
                hits = entry["latest"]["hits"]["hits"]
                if hits:
                    found[str(entry["key"]["agent"])] = hits[0]["_source"]
            after = bucket.get("after_key")
            if not after or not bucket.get("buckets"):
                return found

    def search_all(self, indices, body, limit=100000):
        index_path = urllib.parse.quote(indices, safe="*,-_")
        query = copy.deepcopy(body)
        query["size"] = 500
        query["sort"] = ["_doc"]
        result = self.request("POST", "/" + index_path + "/_search?scroll=1m", query, allow_404=True)
        if result is None:
            return []
        rows = []
        scroll = None
        try:
            while True:
                scroll = result.get("_scroll_id", scroll)
                hits = result.get("hits", {}).get("hits", [])
                if not hits:
                    return rows
                rows.extend(item["_source"] for item in hits)
                if len(rows) > limit:
                    raise IndexerError("Search safety limit exceeded; state was not published")
                if not scroll:
                    return rows
                result = self.request("POST", "/_search/scroll", {"scroll": "1m", "scroll_id": scroll})
        finally:
            if scroll:
                try:
                    self.request("DELETE", "/_search/scroll", {"scroll_id": [scroll]})
                except IndexerError:
                    pass

    def users_for(self, agent_id, run_id):
        if not run_id:
            return []
        return self.search_all(self.config.get("source_indices", "wazuh-archives-*"), {"query": {"bool": {"filter": [
            {"term": {"agent.id": agent_id}}, {"term": {"data." + AUDIT + ".kind": "user"}},
            {"term": {"data." + AUDIT + ".run_id": run_id}}]}}}, self.config.get("max_users_per_host", 10000))

    def previous_users(self, alias):
        result = {}
        for source in self.search_all(alias, {"query": {"term": {"document_kind": "user"}}}):
            result.setdefault(source["agent_id"], []).append(source)
        return result

    def publish(self, alias, prefix, documents, now):
        # No generation is deleted automatically. Failed publication leaves the old alias intact.
        generation = prefix + "-" + now.strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:8]
        self.request("PUT", "/" + generation, {"settings": {"number_of_shards": 1, "number_of_replicas": 0}, "mappings": mappings()})
        batch_size = self.config.get("bulk_batch_size", 500)
        for offset in range(0, len(documents), batch_size):
            lines = []
            for document in documents[offset:offset + batch_size]:
                identity = document["document_kind"] + "\0" + document["agent_id"] + "\0" + document.get("sid", "")
                doc_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
                lines.append(json.dumps({"index": {"_index": generation, "_id": doc_id}}))
                lines.append(json.dumps(document, ensure_ascii=False, allow_nan=False))
            result = self.request("POST", "/_bulk", ("\n".join(lines) + "\n").encode("utf-8"), "application/x-ndjson")
            if result.get("errors"):
                raise IndexerError("Bulk indexing failed; the published alias was not changed")
        self.request("POST", "/" + generation + "/_refresh")
        count = self.request("GET", "/" + generation + "/_count").get("count")
        if count != len(documents):
            raise IndexerError("Published document count did not reconcile; alias unchanged")
        old = self.request("GET", "/_alias/" + alias, allow_404=True) or {}
        actions = [{"remove": {"index": name, "alias": alias}} for name in old]
        actions.append({"add": {"index": generation, "alias": alias}})
        self.request("POST", "/_aliases", {"actions": actions})
        return generation

    def cleanup_generations(self, alias, prefix, keep):
        """Explicit opt-in cleanup of only this tool's unaliased derived indices."""
        if keep == 0:
            return 0
        if keep < 2:
            raise ValueError("retention_keep_generations must be 0 or at least 2")
        candidates = self.request("GET", "/" + prefix + "-*/_alias", allow_404=True) or {}
        pattern = re.compile(re.escape(prefix) + r"-\d{14}-[0-9a-f]{8}$")
        own = sorted((name for name in candidates if pattern.fullmatch(name)), reverse=True)
        protected = set(own[:keep])
        deleted = 0
        for name in own:
            # Any alias, including an unexpected user-created alias, protects an index from cleanup.
            if name in protected or candidates[name].get("aliases"):
                continue
            self.request("DELETE", "/" + name)
            deleted += 1
        return deleted


def load_inventory(path):
    with Path(path).open("r", encoding="utf-8-sig") as handle:
        inventory = json.load(handle)
    if not isinstance(inventory, list):
        raise ValueError("Inventory must be a JSON list")
    return inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true", help="Execute one refresh; use a service timer for recurrence")
    args = parser.parse_args()
    if not args.once:
        parser.error("Use --once; recurrence belongs to the provided systemd timer")
    config = private_json(args.config)
    alias = config.get("target_alias", "lab-password-audit-current")
    prefix = config.get("target_prefix", "lab-password-audit-state-v2")
    for name in (alias, prefix):
        if not re.fullmatch(r"lab-password-audit-[a-z0-9_-]+", name):
            raise ValueError("Target alias/prefix must use the dedicated lab-password-audit- namespace")
    lock = None
    try:
        if os.name == "posix":
            import fcntl
            lock = open(config.get("lock_file", "/run/wazuh-password-audit.lock"), "a", encoding="ascii")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        now = dt.datetime.now(UTC)
        indexer = Indexer(config)
        inventory = load_inventory(config["inventory_file"])
        summaries = indexer.latest_summaries()
        users = {agent_id: indexer.users_for(agent_id, audit(summary).get("run_id"))
                 for agent_id, summary in summaries.items()}
        previous = indexer.previous_users(alias)
        documents = build_documents(inventory, summaries, users, previous, now,
            config.get("max_age_seconds", 7200), config.get("future_tolerance_seconds", 300),
            config.get("publication_ttl_seconds", 300))
        generation = indexer.publish(alias, prefix, documents, now)
        retention_warning = False
        try:
            deleted = indexer.cleanup_generations(alias, prefix, config.get("retention_keep_generations", 0))
        except (IndexerError, ValueError):
            # State has already been published. A cleanup problem must not undo a valid view.
            deleted, retention_warning = 0, True
        hosts = [doc for doc in documents if doc["document_kind"] == "host"]
        print(json.dumps({"status": "published", "index": generation, "host_count": len(hosts),
            "user_count": len(documents) - len(hosts), "hosts_ok": sum(doc["host_state"] == "ok" for doc in hosts),
            "derived_generations_deleted": deleted, "retention_warning": retention_warning}, ensure_ascii=True))
    finally:
        if lock:
            lock.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Avoid credential/response dumps and Python tracebacks in service journals.
        print("Password state refresh failed: " + str(error), file=sys.stderr)
        sys.exit(1)
```
