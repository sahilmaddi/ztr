import json
import sys
from pathlib import Path


report_path = Path(sys.argv[1])
report = json.loads(report_path.read_text(encoding="utf-8"))
print(json.dumps(report, indent=2))
if report.get("status") != "passed":
    raise SystemExit(f"Regression analysis returned {report.get('status')!r}")
