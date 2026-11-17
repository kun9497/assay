import contextlib
import io
import runpy
import unittest
from pathlib import Path


check = runpy.run_path(str(Path(__file__).with_name("check-release-ci.py")))["check"]


class ReleaseCITest(unittest.TestCase):
    def setUp(self):
        self.run_data = dict(id=42, head_sha="abc", head_branch="main", event="push",
                             status="completed", conclusion="success", html_url="ci-run")
        self.jobs = [dict(name=name, conclusion="success") for name in
                     ("build", "suse-feed", "other-os (macos-latest)", "other-os (windows-latest)")]

    def verify(self, runs, jobs, count=None):
        def get(path):
            if path == "repos/org/assay/actions/workflows/ci.yml/runs?event=push&branch=main&head_sha=abc&per_page=1":
                return {"workflow_runs": runs}
            self.assertEqual(path, "repos/org/assay/actions/runs/42/jobs?filter=latest&per_page=100")
            return {"jobs": jobs, "total_count": len(jobs) if count is None else count}
        with contextlib.redirect_stdout(io.StringIO()):
            check("org/assay", "abc", get)

    def test_only_complete_main_ci_can_publish(self):
        self.verify([self.run_data], self.jobs)
        for field, value in (("head_sha", "old"), ("event", "pull_request"), ("head_branch", "topic"),
                             ("status", "in_progress"), ("conclusion", "failure")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify([dict(self.run_data, **{field: value})], self.jobs)
        with self.assertRaises(ValueError):
            self.verify([], self.jobs)
        with self.assertRaises(ValueError):
            self.verify([self.run_data], self.jobs[1:])
        with self.assertRaises(ValueError):
            self.verify([self.run_data], self.jobs + [dict(name="new check", conclusion="skipped")])
        with self.assertRaises(ValueError):
            self.verify([self.run_data], self.jobs, count=101)


if __name__ == "__main__":
    unittest.main()
