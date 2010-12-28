OPTS="-x .ut.rb -x .ts.rb -q"
BASE="$(dirname "$0")"
MSFDIR="${BASE}/.."
DOCDIR="${BASE}/api"

echo "Putting docs in ${DOCDIR}"

echo "Generating rex..."
rdoc $OPTS -t "Rex Documentation" -o ${DOCDIR}/rex ${MSFDIR}/lib/rex
echo "Generating msfcore"
rdoc $OPTS -t "Framework Core Documentation" -o ${DOCDIR}/msfcore ${MSFDIR}/lib/msf/core
echo "Generating msfbase"
rdoc $OPTS -t "Framework Base Documentation" -o ${DOCDIR}/msfbase ${MSFDIR}/lib/msf/base
echo "Generating msfui"
rdoc $OPTS -t "Framework UI Documentation" -o ${DOCDIR}/msfui ${MSFDIR}/lib/msf/ui
