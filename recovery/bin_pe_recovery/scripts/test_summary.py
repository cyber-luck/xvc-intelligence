"""Roda o pytest e grava um resumo JSON (para anexar ao relatorio com --tests-json).

Uso: python scripts/test_summary.py SAIDA.json [args extras do pytest]
"""
import datetime
import json
import os
import sys

import pytest


class Collector:
    def __init__(self):
        self.outcomes = {}
        self.failed = []
        self.skipped_reasons = {}

    def pytest_runtest_logreport(self, report):
        if report.when == "call" or (report.when == "setup" and report.outcome != "passed"):
            self.outcomes[report.outcome] = self.outcomes.get(report.outcome, 0) + 1
            if report.outcome == "failed":
                self.failed.append(report.nodeid)
            if report.outcome == "skipped":
                reason = str(report.longrepr[-1]) if isinstance(report.longrepr, tuple) else str(report.longrepr)
                self.skipped_reasons[reason] = self.skipped_reasons.get(reason, 0) + 1


def main():
    out = sys.argv[1]
    extra = sys.argv[2:]
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    c = Collector()
    rc = pytest.main(["-q", "-p", "no:cacheprovider", os.path.join(root, "tests"), *extra], plugins=[c])
    summary = {"command": "pytest.main([-q, tests] + extra) via scripts/test_summary.py; extra=" + " ".join(extra),
               "XVC_PATH_set": bool(os.environ.get("XVC_PATH")), "XVC_FULL": os.environ.get("XVC_FULL") == "1",
               "exit_code": int(rc), "outcomes": c.outcomes, "failed": c.failed, "skipped_reasons": c.skipped_reasons,
               "python": sys.version.split()[0], "pytest": pytest.__version__,
               "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(json.dumps(summary, indent=1, ensure_ascii=False))
    return int(rc)


if __name__ == "__main__":
    raise SystemExit(main())
