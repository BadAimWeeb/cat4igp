#!/usr/bin/env bash
set -euo pipefail

check_tag() {
    local actual encoded_tag
    encoded_tag=$(jq -rn --arg tag "$TAG" '$tag | @uri') || return 1
    actual=$(gh api "repos/$GH_REPO/commits/refs/tags/$encoded_tag" --jq .sha) || return 1
    if [[ $actual != "$SOURCE_SHA" ]]; then
        echo "Release tag $TAG does not resolve to source commit $SOURCE_SHA" >&2
        return 1
    fi
}

if [[ ${1:-} == --check ]]; then
    GH_REPO=example/repo TAG=v1.2.3 SOURCE_SHA=0123456789012345678901234567890123456789
    gh() {
        [[ $1 == api && $2 == "$expected_path" && $3 == --jq && $4 == .sha ]] || return 1
        printf '%s\n' "$resolved"
    }
    expected_path=repos/example/repo/commits/refs/tags/v1.2.3
    resolved=$SOURCE_SHA
    check_tag || { echo 'Matching tag rejected' >&2; exit 1; }
    TAG='v1.2.3/#%2F'
    expected_path='repos/example/repo/commits/refs/tags/v1.2.3%2F%23%252F'
    check_tag || { echo 'Encoded tag rejected' >&2; exit 1; }
    resolved=abcdefabcdefabcdefabcdefabcdefabcdefabcd
    if check_tag 2>/dev/null; then echo 'Moved tag accepted' >&2; exit 1; fi
    gh() { return 1; }
    if check_tag; then echo 'Unresolvable tag accepted' >&2; exit 1; fi
else
    [[ $# == 0 ]] || { echo 'Usage: check-release-tag.sh [--check]' >&2; exit 1; }
    check_tag
fi
