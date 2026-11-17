"""Require successful main CI for the exact commit about to be published."""

import json
import os
import subprocess
import sys


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", path]))


def check(repo, commit, get=api):
    actions = f"repos/{repo}/actions"
    runs = get(f"{actions}/workflows/ci.yml/runs?event=push&branch=main&head_sha={commit}&per_page=1")
    if not runs["workflow_runs"]:
        raise ValueError(f"no push CI run on main for {commit}")
    run = runs["workflow_runs"][0]
    if (run["head_sha"], run["head_branch"], run["event"], run["status"], run["conclusion"]) != (
        commit, "main", "push", "completed", "success"
    ):
        raise ValueError(f"main CI has not succeeded for {commit}: {run['html_url']}")

    jobs = get(f"{actions}/runs/{run['id']}/jobs?filter=latest&per_page=100")
    required = {"build", "suse-feed", "other-os (macos-latest)", "other-os (windows-latest)"}
    missing = required.difference(job["name"] for job in jobs["jobs"])
    unsuccessful = [job["name"] for job in jobs["jobs"] if job["conclusion"] != "success"]
    if missing or unsuccessful or jobs["total_count"] != len(jobs["jobs"]):
        raise ValueError(f"incomplete CI in {run['html_url']}; missing={sorted(missing)}, unsuccessful={unsuccessful}")
    print(f"Verified {jobs['total_count']} successful main CI jobs for {commit}: {run['html_url']}")


if __name__ == "__main__":
    try:
        check(os.environ["GITHUB_REPOSITORY"], sys.argv[1])
    except (ValueError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit(f"Release blocked: {error}")
