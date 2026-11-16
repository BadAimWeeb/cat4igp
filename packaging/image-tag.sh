#!/usr/bin/env bash
set -euo pipefail

image_tag() {
    local ref=$1 sha=$2 version=$3
    if [[ $ref == refs/tags/* ]]; then
        [[ $ref == "refs/tags/v$version" && $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
        printf 'v%s\n' "$version"
    else
        [[ $sha =~ ^[0-9a-f]{40}$ ]] || return 1
        printf '%s\n' "$sha"
    fi
}

if [[ ${1:-} == --check ]]; then
    [[ $# == 1 ]]
    first=abcdef0123456789012345678901234567890123
    second=abcdef0999999999999999999999999999999999
    [[ $(image_tag refs/heads/main "$first" 1.2.3) == "$first" ]]
    [[ $(image_tag refs/heads/main "$second" 1.2.3) == "$second" ]]
    [[ $(image_tag refs/tags/v1.2.3 "$first" 1.2.3) == v1.2.3 ]]
    if image_tag refs/tags/v1.2.4 "$first" 1.2.3; then exit 1; fi
    if image_tag refs/heads/main abcdef0 1.2.3; then exit 1; fi
else
    [[ $# == 0 ]]
    version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' server/Cargo.toml)
    image_tag "$REF" "$SHA" "$version"
fi
