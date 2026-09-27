from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from analyse_logs import analyse, parse_line  # noqa: E402

def test_parse_valid_line():
    line = '203.0.113.1 - - [28/Sep/2026:09:00:01 +0100] "GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
    record = parse_line(line)
    assert record is not None
    assert record["ip"] == "203.0.113.1"
    assert record["path"] == "/"
    assert record["status"] == "200"

def test_sample_dataset():
    result = analyse(ROOT / "data" / "sample_access.log")
    assert result["events"] == 8
    assert result["status_classes"]["2xx"] == 3
    assert result["status_classes"]["4xx"] == 5
    assert result["suspicious_events"] >= 2
