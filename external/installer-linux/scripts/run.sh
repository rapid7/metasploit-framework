#!/bin/sh

export LINK=$(which "$0")
export NAME=$(basename "$0")
while [ -L "$LINK" ]; do
	LAST=$LINK
	LINK="$(readlink "$LINK")"
	if [ ! -L "$LINK" ]; then
		break
	fi
done

# Chop it twice
BASE=$(dirname "$LAST")
BASE=$(dirname "$BASE")
export BASE

export PATH=${BASE}/app:$PATH
export LD_LIBRARY_PATH=${BASE}/lib:$LD_LIBRARY_PATH
unset GEM_PATH
unset MY_RUBY_HOME
unset RUBY_VERSION
unset RUBY_OPTS

if [ -f "${BASE}/msf3/${NAME}" ]; then
	exec ${BASE}/msf3/${NAME} $@
fi

exec ${NAME} $@

