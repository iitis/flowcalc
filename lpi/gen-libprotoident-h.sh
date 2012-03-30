#!/bin/sh
#
# Generate a clean C libprotoident.h header file
#

path=`find /usr/include/ /usr/local/include/ ~/local/include -name "libprotoident.h" -print -quit`

if [ -z "$path" ]; then
	echo "gen-libprotoident-h: libprotoident.h not found" >&2
	return 1
fi

sed "$path" -r -e '/^#include/ { /\.h>$/!d }' -e '/std::/d' > lpi/libprotoident.h
