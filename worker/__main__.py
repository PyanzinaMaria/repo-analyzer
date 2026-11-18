"""Entry point: ``python -m worker`` from the repository root."""

from __future__ import annotations

import logging
import sys
import time

from worker import pipeline, queue
from worker.config import load_config

logger = logging.getLogger("worker")


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    cfg = load_config()
    queue_dir = cfg.queue_dir
    logger.info(
        "Worker started: data_dir=%s poll=%.1fs enable_ai=%s",
        cfg.data_dir,
        cfg.poll_interval_seconds,
        cfg.enable_ai,
    )

    jobs_pipeline = pipeline.Pipeline(cfg)
    while True:
        jobs = queue.claimed_jobs(queue_dir) + queue.pending_jobs(queue_dir)
        for job_path in jobs:
            claimed = job_path if job_path.name.endswith(queue.CLAIMED_SUFFIX) else queue.claim(job_path)
            if claimed is None:
                continue
            job = queue.parse_job(claimed)
            if job is None:
                logger.warning("Dropping unparseable job %s", claimed.name)
            elif queue.is_stale(job, cfg.uploads_dir):
                logger.info("Dropping stale job %s (scan no longer known to the frontend)", claimed.name)
            else:
                try:
                    jobs_pipeline.process(job)
                except Exception:  # noqa: BLE001 — the manifest already says 'fail'; keep the loop alive
                    logger.exception("Unexpected pipeline error for %s", claimed.name)
            queue.release(claimed)
        time.sleep(cfg.poll_interval_seconds)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("Worker stopped")
        sys.exit(0)
