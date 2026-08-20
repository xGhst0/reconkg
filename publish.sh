#!/usr/bin/env bash
#
# Publish reconkg to github.com/xghst0/reconkg.
#
# Run this from inside the unzipped reconkg directory:
#
#     chmod +x publish.sh && ./publish.sh
#
# On credentials, deliberately: this script never asks you for a token and
# never accepts one as an argument. A token passed on a command line lands in
# your shell history and is visible in `ps` to every user on the box, which is
# a bad trade for saving one prompt. Authentication is delegated to `gh auth
# login` or to git's own credential helper, both of which handle the secret
# without it passing through here.
#
# Safe to re-run. It checks the state before each step and skips what is
# already done.

set -euo pipefail

USER="xghst0"
REPO="reconkg"
REMOTE="https://github.com/${USER}/${REPO}.git"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*"; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #

command -v git >/dev/null || die "git is not installed. apt install git"

[[ -f pyproject.toml && -d reconkg ]] || die \
    "run this from inside the reconkg directory (no pyproject.toml here)"

bold "==> Checking what is about to be published"

# The .gitignore excludes corpora, feeds and caches. Verify that actually
# held rather than trusting it: a *.db file in a public repo is someone
# else's licence problem and possibly your scan history.
if git rev-parse --git-dir >/dev/null 2>&1; then
    if git ls-files | grep -qE '\.(db|db-wal|db-shm)$'; then
        die "a database file is staged for commit. Those are built locally
     and must not be published -- check .gitignore before continuing."
    fi
    if git ls-files | grep -qE '(^|/)feeds/'; then
        die "downloaded feed data is staged. Same reason; do not publish it."
    fi
fi

# --------------------------------------------------------------------------- #
# Repository
# --------------------------------------------------------------------------- #

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    bold "==> Initialising the repository"
    git init -q
    git add -A
    git commit -q -m "reconkg: vulnerability triage with provenance"
else
    echo "    repository already initialised"
    if ! git diff --quiet || ! git diff --cached --quiet; then
        bold "==> Committing local changes"
        git add -A
        git commit -q -m "reconkg: update"
    fi
fi

git rev-parse --verify HEAD >/dev/null 2>&1 || die "nothing committed"
git branch -M main

FILES=$(git ls-files | wc -l)
echo "    ${FILES} files, $(git rev-list --count HEAD) commit(s), branch main"

# --------------------------------------------------------------------------- #
# Remote
# --------------------------------------------------------------------------- #

if git remote get-url origin >/dev/null 2>&1; then
    CURRENT=$(git remote get-url origin)
    if [[ "$CURRENT" != "$REMOTE" ]]; then
        warn "    origin points at ${CURRENT}; repointing at ${REMOTE}"
        git remote set-url origin "$REMOTE"
    else
        echo "    origin already set"
    fi
else
    git remote add origin "$REMOTE"
    echo "    origin -> ${REMOTE}"
fi

# --------------------------------------------------------------------------- #
# Create the repo on GitHub, if gh can
# --------------------------------------------------------------------------- #

if command -v gh >/dev/null 2>&1; then
    if ! gh auth status >/dev/null 2>&1; then
        bold "==> GitHub CLI is installed but not logged in"
        echo "    Running 'gh auth login'. Choose HTTPS and authenticate in"
        echo "    the browser; the token is stored by gh, not by this script."
        gh auth login
    fi
    if gh repo view "${USER}/${REPO}" >/dev/null 2>&1; then
        echo "    ${USER}/${REPO} already exists"
    else
        bold "==> Creating ${USER}/${REPO} (public)"
        gh repo create "${USER}/${REPO}" --public \
            --description "Vulnerability triage with provenance. Resolves CVEs from locally built corpora and emits verification commands classified by what running them does to the target." \
            --source=. --remote=origin 2>/dev/null \
        || gh repo create "${USER}/${REPO}" --public
    fi
else
    warn "==> GitHub CLI (gh) not found."
    echo "    Either install it:    apt install gh"
    echo "    or create the repo by hand at:"
    echo "        https://github.com/new"
    echo "    Name it '${REPO}', make it Public, and add NO README, NO"
    echo "    .gitignore and NO licence -- this repo already has all three,"
    echo "    and GitHub's versions would collide on the first push."
    echo
    read -r -p "    Press Enter once the empty repo exists (or Ctrl-C to stop): " _
fi

# --------------------------------------------------------------------------- #
# Push
# --------------------------------------------------------------------------- #

bold "==> Pushing to ${REMOTE}"
echo "    If prompted for a password, use a Personal Access Token, not your"
echo "    account password -- GitHub stopped accepting passwords in 2021."
echo "    Create one at https://github.com/settings/tokens with 'repo' scope."
echo

if git push -u origin main; then
    bold "==> Done"
    echo
    echo "    https://github.com/${USER}/${REPO}"
    echo
    echo "    Install on Kali with:"
    echo
    echo "    git clone https://github.com/${USER}/${REPO} && cd ${REPO} \\"
    echo "      && pip install -e . --break-system-packages \\"
    echo "      && python -m reconkg.selfcheck"
    echo
else
    die "push failed. Common causes:
       - the repo does not exist yet on GitHub
       - the remote already has commits (try: git pull --rebase origin main)
       - authentication: run 'gh auth login', or use a Personal Access Token
         as the password rather than your account password"
fi
