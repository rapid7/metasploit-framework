OPTS="-x .ut.rb -x .ts.rb -q"

echo "Generating rex..."
rdoc $OPTS -t "Rex Documentation" -o doc/rex lib/rex
echo "Generating msfcore"
rdoc $OPTS -t "Framework Core Documentation" -o doc/msfcore lib/msf/core
echo "Generating msfbase"
rdoc $OPTS -t "Framework Base Documentation" -o doc/msfbase lib/msf/base
echo "Generating msfui"
rdoc $OPTS -t "Framework UI Documentation" -o doc/msfui lib/msf/ui
