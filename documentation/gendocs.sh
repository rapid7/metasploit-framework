OPTS="-x .ut.rb -x .ts.rb -q"
BASE="documentation/api"

echo "Generating rex..."
rdoc $OPTS -t "Rex Documentation" -o $BASE/rex lib/rex
echo "Generating msfcore"
rdoc $OPTS -t "Framework Core Documentation" -o $BASE/msfcore lib/msf/core
echo "Generating msfbase"
rdoc $OPTS -t "Framework Base Documentation" -o $BASE/msfbase lib/msf/base
echo "Generating msfui"
rdoc $OPTS -t "Framework UI Documentation" -o $BASE/msfui lib/msf/ui
