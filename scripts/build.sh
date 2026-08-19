#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
version=${1:-dev}
target_os=${GOOS:-$(go env GOOS)}
target_arch=${GOARCH:-$(go env GOARCH)}
output_directory=${OUTPUT_DIRECTORY:-"$repository_root/dist"}
mkdir -p "$output_directory"

commit_value=$(git -C "$repository_root" rev-parse --short HEAD 2>/dev/null || printf '%s' unknown)
build_date_value=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ldflags="-s -w -X main.version=$version -X main.commit=$commit_value -X main.buildDate=$build_date_value"
extension=
if [ "$target_os" = windows ]; then
    extension=.exe
fi
artifact_path="$output_directory/dnsleaf-$target_os-$target_arch$extension"
GOOS="$target_os" GOARCH="$target_arch" go build -mod=vendor -trimpath -ldflags "$ldflags" -o "$artifact_path" "$repository_root"
printf 'built %s\n' "$artifact_path"
