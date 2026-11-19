#!/usr/bin/env bash
set -euo pipefail
# Generate a Zig module that embeds the version read from the root VERSION file.
# Usage: gen_version.sh <version_file> <output_zig_file>

version_file="${1:?version file required}"
output_file="${2:?output file required}"

version=$(tr -d ' \t\r\n' < "$version_file")
printf 'pub const VERSION = "%s";\n' "$version" > "$output_file"
