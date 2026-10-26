#!/bin/sh
# One-time npm setup for a maintainer (see docs/releasing.md). Needs an npm
# account with two-factor authentication that belongs to the `airlox` org.
#
#   sh packaging/npm/bootstrap.sh claim   publish 0.0.1 placeholders, so the six
#                                         names exist (and nobody else takes them)
#   sh packaging/npm/bootstrap.sh trust   let .github/workflows/release.yml, in the
#                                         `release` environment, publish them
#
# npm can trust a workflow only for packages that exist, and a new trust must
# publish within two days, so run `trust` just before tagging the first release.
set -eu

npm="npx -y npm@11.21.1"
packages="airlox @airlox/darwin-arm64 @airlox/darwin-x64 @airlox/linux-arm64 @airlox/linux-x64 @airlox/win32-x64"

echo "npm user: $($npm whoami)"
case "${1:-}" in
claim)
    tmp=$(mktemp -d)
    for p in $packages; do
        if $npm view "$p" version > /dev/null 2>&1; then
            echo "$p already exists"
            continue
        fi
        dir="$tmp/$(echo "$p" | tr / _)"
        mkdir "$dir"
        cat > "$dir/package.json" <<EOF
{
  "name": "$p",
  "version": "0.0.1",
  "description": "Reserved for Airlox (https://github.com/claudezss/airlox); the first release is coming",
  "license": "MIT OR Apache-2.0",
  "repository": { "type": "git", "url": "git+https://github.com/claudezss/airlox.git" }
}
EOF
        (cd "$dir" && $npm publish --access public)
    done
    ;;
trust)
    for p in $packages; do
        $npm trust github "$p" --file release.yml --repo claudezss/airlox --env release --allow-publish --yes
    done
    ;;
*)
    echo "usage: sh packaging/npm/bootstrap.sh claim|trust" >&2
    exit 2
    ;;
esac
