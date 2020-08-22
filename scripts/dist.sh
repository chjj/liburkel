#!/bin/bash

# dist.sh - github release for packages
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/chjj

set -e

REPO='liburkel'
OWNER='handshake-org'
CHECK='include/urkel.h'
TOKEN=

type curl > /dev/null 2>& 1
type git > /dev/null 2>& 1
type gpg > /dev/null 2>& 1
type jq > /dev/null 2>& 1
type sha256sum > /dev/null 2>& 1

test -d .git
test -f "$CHECK"

dist_archive() {
  local tag="$1"
  local fmt="$2"
  local ver=$(echo "$tag" | tr -d 'v')
  local name="${REPO}-${ver}.${fmt}"
  local prefix="${REPO}-${ver}/"

  echo "Archiving $tag (${fmt}):" >& 2
  echo "  ARCHIVE $name" >& 2
  echo "  SIGN ${name}.asc" >& 2

  rm -f "$name"
  rm -f "${name}.asc"

  git archive -o "$name" --prefix "$prefix" "$tag"
  gpg --quiet --detach-sign --armor "$name"

  echo "$name"
}

github_post() {
  local url="$1"
  local type="$2"

  shift
  shift

  echo "  POST $url" >& 2

  curl -s -X POST                       \
       -H 'Accept: application/json'    \
       -H "Authorization: token $TOKEN" \
       -H "Content-Type: $type"         \
       "$@" "$url"
}

get_description() {
  local tag="$1"
  local state=0

  while IFS= read -r line; do
    case $state in
      0)
        if echo "$line" | grep -q "^## ${tag}$"; then
          state=1
        fi
      ;;
      1)
        if test -n "$line"; then
          echo 'Invalid changelog.' >& 2
          exit 1
        fi
        state=2
      ;;
      2)
        if echo "$line" | grep -q '^## v[0-9]'; then
          break
        fi
        echo -n "${line}\n" | sed -e 's/"/\\"/g'
      ;;
    esac
  done < CHANGELOG.md

  if test $state -ne 2; then
    echo 'Invalid changelog.' >& 2
    exit 1
  fi
}

github_release() {
  local tag="$1"
  local commit=$(git rev-parse "$tag")
  local desc=$(get_description "$tag")
  local url="https://api.github.com/repos/${OWNER}/${REPO}/releases"
  local body=$(cat <<EOF
    {
      "tag_name": "${tag}",
      "target_commitish": "${commit}",
      "name": "${REPO} ${tag}",
      "body": "${desc}",
      "draft": false,
      "prerelease": false
    }
EOF
  )

  echo "Releasing $tag (${commit}):" >& 2

  github_post "$url" application/json --data-raw "$body" \
    | jq .upload_url                                     \
    | tr -d '"'                                          \
    | cut -d '{' -f 1
}

github_upload() {
  local name="$1"
  local url="$2"
  local type="$3"
  local res=

  echo "Uploading ${name}:" >& 2

  res=$(github_post "${url}?name=${name}&label=${name}" \
                    "$type" --data-binary "@${name}")

  url=$(echo "$res" | jq .browser_download_url | tr -d '"')

  echo "  URL $url" >& 2
}

archive_main() {
  local tag="$1"
  local tgz=$(dist_archive "$tag" tar.gz)
  local zip=$(dist_archive "$tag" zip)

  sha256sum "$tgz" "$zip" > sha256sums.txt
}

publish_main() {
  local tag="$1"
  local tgz=$(dist_archive "$tag" tar.gz)
  local zip=$(dist_archive "$tag" zip)
  local url=$(github_release "$tag")

  test -n "$url"

  sha256sum "$tgz" "$zip" > sha256sums.txt

  github_upload "$tgz" "$url" application/gzip
  github_upload "${tgz}.asc" "$url" text/plain
  github_upload "$zip" "$url" application/zip
  github_upload "${zip}.asc" "$url" text/plain
  github_upload sha256sums.txt "$url" text/plain
}

clean_main() {
  rm -f ${REPO}-*.tar.gz
  rm -f ${REPO}-*.tar.gz.asc
  rm -f ${REPO}-*.zip
  rm -f ${REPO}-*.zip.asc
  rm -f sha256sums.txt
}

main() {
  local action="$1"
  local tag="$2"

  if test -z "$action"; then
    echo 'Usage: ./dist.sh [action] [tag]' >& 2
    exit 1
  fi

  if test "$action" = 'clean'; then
    clean_main
    exit 0
  fi

  if test -z "$tag"; then
    tag=$(git tag -l 'v*' --sort v:refname | tail -n 1)
  fi

  if ! git rev-parse "$tag" > /dev/null 2>& 1; then
    echo 'Invalid tag.' >& 2
    exit 1
  fi

  case "$action" in
    archive)
      archive_main "$tag"
    ;;
    publish)
      echo -n 'GitHub Token: '
      IFS= read -rs TOKEN
      echo ''
      test -n "$TOKEN"

      publish_main "$tag"
    ;;
    *)
      echo 'Invalid action.' >& 2
      exit 1
    ;;
  esac
}

main "$@"
