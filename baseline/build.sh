#!/bin/sh
# SPDX-License-Identifier: ISC
# Pristine build of tinytalk's door-lock sample on the DWM3001CDK with
# release.conf and no-lto.conf, plus the named overlays from this directory
# (nothread also loads the stub seam; tinygrid swaps OpenThread for this
# repo's stack; tinygrid-radio after it, for its own radio driver). Run from
# inside an nRF Connect SDK v3.3.0
# workspace with west on PATH, then read the map with mapsize.py.
#
# Usage: build.sh <tinytalk> <build-dir> [overlay ...]
#   e.g. build.sh ../tinytalk build/trim trim
#   map: <build-dir>/door-lock/zephyr/zephyr.map
set -e
[ $# -ge 2 ] || { echo "usage: $0 <tinytalk> <build-dir> [overlay ...]" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
app=$1/samples/door-lock
out=$2
shift 2
conf="$here/release.conf;$here/no-lto.conf"
mods=
for o in "$@"; do
	conf="$conf;$here/$o.conf"
	if [ "$o" = nothread ]; then
		mods="-DEXTRA_ZEPHYR_MODULES=$here/stub-seam"
	elif [ "$o" = tinygrid ]; then
		conf="${conf%;*};$here/../ports/zephyr/tinygrid.conf"
		mods="-DEXTRA_ZEPHYR_MODULES=$(cd "$here/.." && pwd)"
	elif [ "$o" = tinygrid-radio ]; then
		conf="${conf%;*};$here/../ports/zephyr/tinygrid-radio.conf"
	fi
done
west build -p always -b decawave_dwm3001cdk -d "$out" "$app" -- "-DEXTRA_CONF_FILE=$conf" $mods
