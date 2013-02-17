#!/usr/bin/env ruby

# 1. host_id and host_int can captured from DEBUG logs *OR*
#    host_id can be extracted from ~/.dropbox/config.dbx and
#    host_int can be "sniffed" from Dropbox LAN sync traffic
# 2. export DBDEV=a2y6shya
# 3. Restart dropboxd and capture its output

require 'digest/sha1'
require 'json'

if ARGV.length < 1
	$stderr.puts "Usage: " + $0 + " <dropbox_jack.txt> file"
	exit -1
end

data = open(ARGV[0], "r").read()

host_id, host_int = JSON.parse(data)

now = Time.now.to_i.to_s
secret = host_id + 'sKeevie4jeeVie9bEen5baRFin9' + now
digest = Digest::SHA1.hexdigest secret
url = "https://www.dropbox.com/tray_login?i=" + host_int.to_s + "&t=" + now + "&v=" + digest + "&url=home&cl=en_US"

puts url
