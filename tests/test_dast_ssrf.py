from __future__ import annotations

import pytest

from app.dast.config import DastConfig
from app.dast.ssrf import DastTargetError, validate_target_url


def test_rejects_bad_scheme() -> None:
    cfg = DastConfig(allow_private_targets=True)
    with pytest.raises(DastTargetError, match="scheme"):
        validate_target_url("ftp://example.com/", cfg)


def test_blocks_metadata_even_when_private_allowed() -> None:
    cfg = DastConfig(allow_private_targets=True)
    with pytest.raises(DastTargetError, match="metadata|link-local|blocked"):
        validate_target_url("http://169.254.169.254/latest/meta-data", cfg)


def test_blocks_private_when_disallowed() -> None:
    cfg = DastConfig(allow_private_targets=False)
    with pytest.raises(DastTargetError):
        validate_target_url("http://127.0.0.1:8001/", cfg)


def test_allows_private_when_enabled() -> None:
    cfg = DastConfig(allow_private_targets=True)
    assert validate_target_url("http://127.0.0.1:8001/", cfg).startswith("http://")
