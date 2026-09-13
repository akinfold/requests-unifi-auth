import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_coverage_badge.py"


@pytest.fixture(scope="module")
def badge():
    spec = importlib.util.spec_from_file_location("build_coverage_badge", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_badge_color_thresholds(badge):
    assert badge.badge_color(90) == "#4c1"
    assert badge.badge_color(84) == "#97ca00"
    assert badge.badge_color(50) == "#e05d44"


def test_read_percent_rounds_coverage(badge, tmp_path):
    source = tmp_path / "coverage.json"
    source.write_text('{"totals":{"percent_covered":83.67}}', encoding="utf-8")
    assert badge.read_percent(source) == 84


def test_render_badge_contains_accessible_value(badge):
    svg = badge.render_badge(84)
    assert 'aria-label="coverage: 84%"' in svg
    assert "<title>coverage: 84%</title>" in svg
    assert "#97ca00" in svg
