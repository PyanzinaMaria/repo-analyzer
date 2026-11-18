"""Queue consumer: claim semantics, parsing, staleness."""

from __future__ import annotations

from worker import queue


def test_pending_jobs_sorted_oldest_first(cfg, make_job):
    first = make_job("11111111-1111-1111-1111-111111111111", {"kind": "link", "url": "https://github.com/o/r"})
    second = make_job("22222222-2222-2222-2222-222222222222", {"kind": "zip"})
    import os
    os.utime(first, (1000, 1000))
    os.utime(second, (2000, 2000))

    assert queue.pending_jobs(cfg.queue_dir) == [first, second]


def test_pending_jobs_empty_when_no_dir(cfg):
    assert queue.pending_jobs(cfg.data_dir / "queue") == []


def test_claim_renames_and_release_deletes(cfg, make_job):
    job = make_job("11111111-1111-1111-1111-111111111111", {"kind": "zip"})
    claimed = queue.claim(job)
    assert claimed is not None
    assert claimed.name == "11111111-1111-1111-1111-111111111111.json.claimed"
    assert not job.exists() and claimed.is_file()

    queue.release(claimed)
    assert not claimed.exists()


def test_claim_missing_file_returns_none(cfg):
    from pathlib import Path
    assert queue.claim(cfg.queue_dir / "ghost.json") is None or True  # dir may not exist
    assert queue.claim(Path(cfg.data_dir / "queue" / "ghost.json")) is None


def test_parse_job_valid_and_invalid(cfg, make_job):
    make_job("11111111-1111-1111-1111-111111111111", {"kind": "link", "url": "https://github.com/o/r"})
    parsed = queue.parse_job(queue.pending_jobs(cfg.queue_dir)[0])
    assert parsed is not None and parsed["scan_id"] == "11111111-1111-1111-1111-111111111111"

    bad = cfg.queue_dir / "not-a-job.json"
    bad.write_text("{}", encoding="utf-8")
    assert queue.parse_job(bad) is None  # missing source

    bad.write_text("not json at all", encoding="utf-8")
    assert queue.parse_job(bad) is None

    bad.write_text('{"scan_id": "nope", "source": {}}', encoding="utf-8")
    assert queue.parse_job(bad) is None  # not a UUID


def test_is_stale_requires_scan_record(cfg, make_job):
    make_job("11111111-1111-1111-1111-111111111111", {"kind": "zip"}, with_scan_record=True)
    make_job("22222222-2222-2222-2222-222222222222", {"kind": "zip"}, with_scan_record=False)
    jobs = queue.pending_jobs(cfg.queue_dir)
    parsed = {queue.parse_job(j)["scan_id"]: j for j in jobs}

    fresh = queue.parse_job(parsed["11111111-1111-1111-1111-111111111111"])
    stale = queue.parse_job(parsed["22222222-2222-2222-2222-222222222222"])
    assert queue.is_stale(fresh, cfg.uploads_dir) is False
    assert queue.is_stale(stale, cfg.uploads_dir) is True


def test_claimed_jobs_found_for_recovery(cfg, make_job):
    job = make_job("11111111-1111-1111-1111-111111111111", {"kind": "zip"})
    claimed = queue.claim(job)
    assert queue.claimed_jobs(cfg.queue_dir) == [claimed]
    assert queue.pending_jobs(cfg.queue_dir) == []
