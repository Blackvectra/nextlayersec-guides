#!/usr/bin/env bash
# Stage the docs source tree under ./_docs and run `mkdocs build`.
#
# MkDocs forbids `docs_dir` being the parent of the config file, so we
# can't point it at the repo root directly. Instead this script copies
# the markdown / static content into ./_docs using plain `find` + `cp`
# (no rsync dependency — runs on minimal CI images).
#
# Used by:
#   - .github/workflows/docs-deploy.yml (CI build)
#   - Local development: `bash scripts/build-docs.sh && mkdocs serve --dev-addr 127.0.0.1:8000 -f mkdocs.yml`
#
# `_docs/` and `site/` are both in .gitignore — never commit.

set -euo pipefail

cd "$(dirname "$0")/.."   # repo root

DEST="${DEST:-_docs}"

# Clean. We don't want stale files from a previous build to ship.
rm -rf "${DEST}"
mkdir -p "${DEST}"

# Content directories — preserve structure. Use plain find/cp so the
# script runs on minimal CI images (no rsync). Only markdown + a small
# set of image extensions are copied.
for d in \
    detections \
    hardening \
    blue-team-playbooks \
    threat-intelligence \
    vulnerabilities \
    frameworks \
    tools \
    detection-workflows \
    purple-team-labs \
    docs ; do
  if [ -d "${d}" ]; then
    while IFS= read -r -d '' f; do
      mkdir -p "${DEST}/$(dirname "${f}")"
      cp "${f}" "${DEST}/${f}"
    done < <(find "${d}" -type f \( \
        -name '*.md' -o \
        -name '*.png' -o \
        -name '*.jpg' -o \
        -name '*.svg' -o \
        -name '*.gif' \) -print0)
  fi
done

# Root-level top-of-site pages. The nav references these by relative
# path; copy them directly into ${DEST}/.
for f in \
    README.md \
    COVERAGE.md \
    CHANGELOG.md \
    CONTRIBUTING.md \
    CODE_OF_CONDUCT.md \
    SECURITY.md \
    SUPPORT.md \
    LICENSE ; do
  [ -f "${f}" ] && cp "${f}" "${DEST}/${f}"
done

echo "Staged $(find ${DEST} -name '*.md' | wc -l) markdown files into ${DEST}/"
