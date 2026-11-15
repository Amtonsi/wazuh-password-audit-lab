"""Pure fixtures and fake Indexer tests. No endpoints or live services are used."""
import copy
import datetime as dt
import json
import unittest

import materialize_password_state as m

NOW = dt.datetime(2026, 11, 15, 4, 0, tzinfo=dt.timezone.utc)
INVENTORY = [{"agent_id": "001", "agent_name": "XP-01", "os": "Windows XP", "expected": True}]


def user(sid="S-1-5-21-1-2-3-1001", run="r1", **changes):
    raw = {"kind": "user", "run_id": run, "username": "Пользователь", "sid": sid,
        "enabled": True, "collection_status": "ok", "age_seconds": 70 * 86400,
        "age_days": 70, "threshold_days": 60, "threshold_exceeded": True,
        "never_expires": False, "expired_reported": False,
        "observed_at_utc": m.iso(NOW - dt.timedelta(minutes=1))}
    raw.update(changes)
    return {"agent": {"id": "001", "name": "XP-01", "ip": "192.168.179.50"},
        "timestamp": m.iso(NOW), "data": {m.AUDIT: raw}}


def summary(run="r1", count=1, **changes):
    raw = {"kind": "summary", "run_id": run, "enumeration_complete": True,
        "identity_complete": True, "expected_user_count": count, "emitted_user_count": count,
        "collection_status": "ok", "policy_read_status": "not_collected", "threshold_days": 60,
        "observed_at_utc": m.iso(NOW - dt.timedelta(minutes=1))}
    raw.update(changes)
    return {"agent": {"id": "001", "name": "XP-01"}, "timestamp": m.iso(NOW), "data": {m.AUDIT: raw}}


def state(s=None, users=None, previous=None, inventory=None):
    return m.build_documents(INVENTORY if inventory is None else inventory,
        {} if s is None else {"001": s}, {} if users is None else {"001": users}, previous or {}, NOW)


class StateTests(unittest.TestCase):
    def test_fresh_snapshot(self):
        docs = state(summary(), [user()])
        self.assertEqual(docs[0]["host_state"], "ok")
        self.assertEqual(docs[0]["over_threshold_count"], 1)
        self.assertEqual(docs[1]["row_state"], "overdue")
        self.assertTrue(docs[1]["is_current_snapshot"])

    def test_age_zero_is_valid(self):
        docs = state(summary(), [user(age_seconds=0, age_days=0, threshold_exceeded=False)])
        self.assertEqual(docs[1]["age_seconds"], 0)
        self.assertEqual(docs[1]["row_state"], "ok")

    def test_latest_error_does_not_resurrect_green(self):
        old = state(summary(), [user(threshold_exceeded=False)])[1:]
        docs = state(summary(run="r2", count=0, collection_status="error", enumeration_complete=False), [], {"001": old})
        self.assertEqual(docs[0]["host_state"], "error")
        self.assertNotIn("over_threshold_count", docs[0])
        self.assertEqual(docs[1]["row_state"], "error")
        self.assertEqual(docs[1]["record_run_id"], "r1")
        self.assertFalse(docs[1]["is_current_snapshot"])

    def test_partial_retains_old_membership(self):
        old = state(summary(), [user()])[1:]
        docs = state(summary(run="r2", count=0, collection_status="partial"), [], {"001": old})
        self.assertEqual(len(docs), 2)
        self.assertEqual(docs[0]["host_state"], "partial")

    def test_complete_new_snapshot_removes_deleted_account(self):
        old = state(summary(), [user()])[1:]
        docs = state(summary(run="r2", count=0), [], {"001": old})
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["over_threshold_count"], 0)

    def test_never_reported_inventory_is_visible(self):
        docs = state()
        self.assertEqual(docs[0]["host_state"], "never_reported")
        self.assertNotIn("over_threshold_count", docs[0])

    def test_observed_only_agent_is_not_expected(self):
        docs = state(summary(), [user()], inventory=[])
        self.assertEqual(docs[0]["host_state"], "ok")
        self.assertIs(docs[0]["expected"], False)
        self.assertEqual(len(docs), 2)

    def test_inventory_member_defaults_to_expected(self):
        docs = state(inventory=[{"agent_id": "001", "agent_name": "XP-01"}])
        self.assertIs(docs[0]["expected"], True)

    def test_inventory_member_explicitly_not_expected(self):
        docs = state(summary(), [user()], inventory=[{"agent_id": "001", "expected": False}])
        self.assertIs(docs[0]["expected"], False)

    def test_stale_measurement_is_not_fresh_after_late_delivery(self):
        s = summary(observed_at_utc=m.iso(NOW - dt.timedelta(hours=3)))
        docs = state(s, [user()])
        self.assertEqual(docs[0]["host_state"], "stale")
        self.assertEqual(docs[1]["row_state"], "stale")

    def test_future_clock_is_not_green(self):
        docs = state(summary(observed_at_utc=m.iso(NOW + dt.timedelta(hours=1))), [user()])
        self.assertEqual(docs[0]["host_state"], "clock_error")

    def test_naive_timestamp_is_invalid(self):
        self.assertIsNone(m.timestamp("2026-11-15T04:00:00"))

    def test_wazuh_offset_without_colon(self):
        self.assertEqual(m.timestamp("2026-11-15T12:00:00.000+0800"), NOW)

    def test_duplicate_sid_is_incomplete(self):
        docs = state(summary(count=2), [user(), user()])
        self.assertEqual(docs[0]["host_state"], "incomplete")
        self.assertIn("duplicate_sid", docs[0]["snapshot_diagnostics"])

    def test_wrong_run_is_not_counted(self):
        docs = state(summary(), [user(run="r0")])
        self.assertEqual(docs[0]["host_state"], "incomplete")

    def test_missing_sid_is_incomplete(self):
        docs = state(summary(), [user(sid="")])
        self.assertFalse(docs[0]["snapshot_complete"])
        self.assertEqual(docs[0]["host_state"], "incomplete")

    def test_missing_user_delivery_is_incomplete(self):
        docs = state(summary(count=2), [user()])
        self.assertEqual(docs[0]["host_state"], "incomplete")
        self.assertNotIn("over_threshold_count", docs[0])

    def test_bad_user_metadata_cannot_be_hidden_by_ok_summary(self):
        docs = state(summary(), [user(collection_status="partial")])
        self.assertEqual(docs[0]["host_state"], "partial")
        self.assertEqual(docs[1]["row_state"], "partial")

    def test_xp_missing_policy_is_unknown_not_zero(self):
        docs = state(summary(), [user()])
        self.assertNotIn("policy_expired_count", docs[0])

    def test_disabled_accounts_not_in_threshold_count(self):
        docs = state(summary(), [user(enabled=False)])
        self.assertEqual(docs[0]["over_threshold_count"], 0)
        self.assertEqual(docs[1]["row_state"], "disabled")

    def test_never_expires_not_itself_overdue(self):
        docs = state(summary(), [user(never_expires=True, threshold_exceeded=False)])
        self.assertEqual(docs[1]["row_state"], "ok")
        self.assertEqual(docs[0]["never_expires_count"], 1)

    def test_cloud_password_excluded(self):
        docs = state(summary(), [user(collection_status="excluded", internet_identity=True)])
        self.assertEqual(docs[1]["row_state"], "excluded")
        self.assertEqual(docs[0]["excluded_count"], 1)
        self.assertEqual(docs[0]["over_threshold_count"], 0)

    def test_strings_from_json_decoder_normalized(self):
        docs = state(summary(enumeration_complete="true", identity_complete="true", expected_user_count="1", emitted_user_count="1"),
            [user(enabled="1", never_expires="false", expired_reported="0", threshold_exceeded="true", age_seconds="6048000")])
        self.assertEqual(docs[0]["host_state"], "ok")
        self.assertIs(docs[1]["enabled"], True)

    def test_publication_expiry_caps_validity(self):
        docs = state(summary(), [user()])
        self.assertEqual(m.timestamp(docs[0]["valid_until"]), NOW + dt.timedelta(minutes=5))

    def test_duplicate_inventory_rejected(self):
        with self.assertRaises(ValueError):
            state(inventory=INVENTORY * 2)

    def test_all_output_fields_have_explicit_mapping(self):
        examples = state(summary(), [user()]) + state()
        allowed = set(m.mappings()["properties"])
        for doc in examples:
            self.assertLessEqual(set(doc), allowed)


class FakeIndexer(m.Indexer):
    def __init__(self, fail_bulk=False, wrong_count=False):
        self.config = {"bulk_batch_size": 1}
        self.calls = []
        self.fail_bulk, self.wrong_count = fail_bulk, wrong_count
        self.count = 0

    def request(self, method, path, data=None, content_type="application/json", allow_404=False):
        self.calls.append((method, path, data))
        if path == "/_bulk":
            self.count += len(data.decode("utf-8").strip().splitlines()) // 2
            return {"errors": self.fail_bulk}
        if path.endswith("/_count"):
            return {"count": self.count - int(self.wrong_count)}
        if path.startswith("/_alias/"):
            return {"lab-password-audit-state-v2-old": {}}
        return {}


class PublicationTests(unittest.TestCase):
    def test_alias_swap_is_last(self):
        fake = FakeIndexer()
        docs = state(summary(), [user()])
        fake.publish("lab-password-audit-current", "lab-password-audit-state-v2", docs, NOW)
        self.assertEqual(fake.calls[-1][1], "/_aliases")
        actions = fake.calls[-1][2]["actions"]
        self.assertEqual(actions[0]["remove"]["index"], "lab-password-audit-state-v2-old")

    def test_bulk_failure_keeps_old_alias(self):
        fake = FakeIndexer(fail_bulk=True)
        with self.assertRaises(m.IndexerError):
            fake.publish("lab-password-audit-current", "lab-password-audit-state-v2", state(), NOW)
        self.assertNotIn("/_aliases", [call[1] for call in fake.calls])

    def test_count_mismatch_keeps_old_alias(self):
        fake = FakeIndexer(wrong_count=True)
        with self.assertRaises(m.IndexerError):
            fake.publish("lab-password-audit-current", "lab-password-audit-state-v2", state(), NOW)
        self.assertNotIn("/_aliases", [call[1] for call in fake.calls])

    def test_cleanup_disabled_by_default(self):
        fake = FakeIndexer()
        self.assertEqual(fake.cleanup_generations("lab-password-audit-current", "lab-password-audit-state-v2", 0), 0)
        self.assertEqual(fake.calls, [])

    def test_cleanup_is_strictly_scoped_and_protects_aliases(self):
        fake = FakeIndexer()
        prefix = "lab-password-audit-state-v2"
        indices = {
            prefix + "-20261115040000-aaaa0000": {"aliases": {"lab-password-audit-current": {}}},
            prefix + "-20261115035900-aaaa0000": {"aliases": {}},
            prefix + "-20261115035800-aaaa0000": {"aliases": {}},
            prefix + "-20261115035700-aaaa0000": {"aliases": {"other-user-alias": {}}},
            prefix + "-manual": {"aliases": {}},
        }
        calls = []
        def request(method, path, data=None, content_type="application/json", allow_404=False):
            calls.append((method, path))
            return indices if method == "GET" else {}
        fake.request = request
        self.assertEqual(fake.cleanup_generations("lab-password-audit-current", prefix, 2), 1)
        self.assertEqual([path for method, path in calls if method == "DELETE"], ["/" + prefix + "-20261115035800-aaaa0000"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
