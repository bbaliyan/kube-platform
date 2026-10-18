#!/usr/bin/env python3
"""Print a cluster Application with every source, and platformRevision, set
to a commit.

  python ci/e2e/point-at-commit.py ci/clusters/kind.yaml COMMIT
"""
import sys

import yaml

path, commit = sys.argv[1:3]
app = yaml.safe_load(open(path, encoding="utf-8"))
for source in app["spec"]["sources"]:
    source["targetRevision"] = commit
    for parameter in source.get("helm", {}).get("parameters", []):
        if parameter["name"] == "platformRevision":
            parameter["value"] = commit
yaml.safe_dump(app, sys.stdout, sort_keys=False)
