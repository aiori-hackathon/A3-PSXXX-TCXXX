import hashlib
import json
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from forensic import db, ingest
from forensic.cli_evidence import app as evidence_app

runner = CliRunner()


def test_ingest_basic():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        tdp = Path(td)
        case_dir = tdp / "cases" / "s1"
        src_dir = tdp / "src"
        src_dir.mkdir(parents=True)

        auth_log = src_dir / "auth.log"
        raw_content = b"dummy log content\n"
        auth_log.write_bytes(raw_content)

        sources_json = src_dir / "sources.json"
        sources_json.write_text(
            json.dumps({
                "case_id": "s1",
                "sources": [
                    {
                        "path": "auth.log",
                        "host": "web01",
                        "source_type": "auth_log",
                        "declared_tz": "UTC",
                    }
                ],
            })
        )

        ingest.ingest(case_dir, sources_json, "test_collector")

        dest = case_dir / "evidence" / "web01__auth.log"
        assert dest.exists()
        assert (case_dir / "manifest.json").exists()
        assert (case_dir / "manifest.sha256").exists()

        # Copied file is read-only
        st_mode = dest.stat().st_mode
        assert (st_mode & 0o777) == 0o444

        # sha256 check
        h = hashlib.sha256()
        h.update(raw_content)
        expected_hash = h.hexdigest()

        with open(case_dir / "manifest.json") as f:
            manifest = json.load(f)
        assert manifest["items"][0]["sha256"] == expected_hash

        assert ingest.verify(case_dir)

        # Test re-ingest (Bug 2 regression)
        ingest.ingest(case_dir, sources_json, "test_collector")
        with open(case_dir / "manifest.json") as f:
            manifest2 = json.load(f)
        assert len(manifest2["items"]) == 1  # Should still have 1 item

        # Test tamper 1-byte
        dest.chmod(0o666)
        dest.write_bytes(b"tampered\n")
        assert not ingest.verify(case_dir)

        # CLI exit code check
        res = runner.invoke(evidence_app, ["verify", "--case", str(case_dir)])
        assert res.exit_code == 1


def test_verify_items_details():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        tdp = Path(td)
        case_dir = tdp / "cases" / "s_items"
        src_dir = tdp / "src"
        src_dir.mkdir(parents=True)

        auth_log = src_dir / "auth.log"
        auth_log.write_bytes(b"auth content\n")

        sources_json = src_dir / "sources.json"
        sources_json.write_text(
            json.dumps({
                "case_id": "s_items",
                "sources": [
                    {
                        "path": "auth.log",
                        "host": "web01",
                        "source_type": "auth_log",
                        "declared_tz": "UTC",
                    }
                ],
            })
        )

        ingest.ingest(case_dir, sources_json, "test")

        # 1. Clean case: verify_items all OK, self-hash OK
        items = ingest.verify_items(case_dir)
        assert len(items) == 2  # manifest.json + 1 evidence file
        manifest_item = next(it for it in items if it["file"] == "manifest.json")
        assert manifest_item["status"] == "OK"
        ev_item = next(it for it in items if it["file"] != "manifest.json")
        assert ev_item["status"] == "OK"

        dest = case_dir / "evidence" / "web01__auth.log"

        # 2. Tampered after 1-byte change
        dest.chmod(0o666)
        dest.write_bytes(b"auth content!\n")
        items_tampered = ingest.verify_items(case_dir)
        ev_item_tampered = next(it for it in items_tampered if it["file"] != "manifest.json")
        assert ev_item_tampered["status"] == "TAMPERED"

        # 3. Missing after deleting stored file
        dest.unlink()
        items_missing = ingest.verify_items(case_dir)
        ev_item_missing = next(it for it in items_missing if it["file"] != "manifest.json")
        assert ev_item_missing["status"] == "MISSING"

        # Re-ingest to restore clean state
        ingest.ingest(case_dir, sources_json, "test")

        # 4. Mismatch for count mismatch
        conn = db.connect(case_dir)
        conn.execute("DELETE FROM evidence")
        conn.commit()
        conn.close()

        items_mismatch = ingest.verify_items(case_dir)
        mismatch_item = next(it for it in items_mismatch if it["file"] == "evidence rows")
        assert mismatch_item["status"] == "MISMATCH"


def test_ingest_verify_failures():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        tdp = Path(td)
        case_dir = tdp / "cases" / "s2"
        src_dir = tdp / "src"
        src_dir.mkdir(parents=True)

        auth_log = src_dir / "auth.log"
        auth_log.write_bytes(b"dummy")

        sources_json = src_dir / "sources.json"
        sources_json.write_text(
            json.dumps({
                "case_id": "s2",
                "sources": [
                    {
                        "path": "auth.log",
                        "host": "web01",
                        "source_type": "auth_log",
                        "declared_tz": "UTC",
                    }
                ],
            })
        )

        ingest.ingest(case_dir, sources_json, "test")
        dest = case_dir / "evidence" / "web01__auth.log"

        # Delete file (chmod first on Windows because 0o444 prevents deletion)
        dest.chmod(0o666)
        dest.unlink()
        assert not ingest.verify(case_dir)

        # Edit manifest
        ingest.ingest(case_dir, sources_json, "test")  # Recreate
        manifest_path = case_dir / "manifest.json"
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
        manifest["items"][0]["sha256"] = "fake"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f)
        # Re-hash manifest for this specific test so the manifest hash check passes
        # but the item hash check fails
        manifest_h = ingest.sha256_chunked(manifest_path)
        (case_dir / "manifest.sha256").write_text(manifest_h)

        assert not ingest.verify(case_dir)


def test_verify_count_mismatch():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        tdp = Path(td)
        case_dir = tdp / "cases" / "s3"
        src_dir = tdp / "src"
        src_dir.mkdir(parents=True)

        auth_log = src_dir / "auth.log"
        auth_log.write_bytes(b"dummy")

        sources_json = src_dir / "sources.json"
        sources_json.write_text(
            json.dumps({
                "case_id": "s3",
                "sources": [
                    {
                        "path": "auth.log",
                        "host": "web01",
                        "source_type": "auth_log",
                        "declared_tz": "UTC",
                    }
                ],
            })
        )

        ingest.ingest(case_dir, sources_json, "test")

        # Mess up DB count without touching manifest
        conn = db.connect(case_dir)
        conn.execute("DELETE FROM evidence")
        conn.commit()
        conn.close()

        assert not ingest.verify(case_dir)
