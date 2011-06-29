OPTS="-x .ut.rb -x .ts.rb -x samples -q"
BASE="$(dirname "$0")"
MSFDIR="${BASE}/.."
DOCDIR="${BASE}/api"
doc=$(which sdoc)

if [ -z $doc ]; then
    doc=$(which rdoc)
fi

echo "Using ${doc} for doc generation"
echo "Putting docs in ${DOCDIR}"

echo "Generating rex..."
$doc $OPTS -t "Rex Documentation" -o ${DOCDIR}/rex ${MSFDIR}/lib/rex
echo "Generating msfcore"
$doc $OPTS -t "Framework Core Documentation" -o ${DOCDIR}/msfcore ${MSFDIR}/lib/msf/core
echo "Generating msfbase"
$doc $OPTS -t "Framework Base Documentation" -o ${DOCDIR}/msfbase ${MSFDIR}/lib/msf/base
echo "Generating msfui"
$doc $OPTS -t "Framework UI Documentation" -o ${DOCDIR}/msfui ${MSFDIR}/lib/msf/ui
