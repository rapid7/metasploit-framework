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

$doc $OPTS -t "Metasploit Documentation" -o ${DOCDIR} ${MSFDIR}/lib/rex ${MSFDIR}/lib/msf

