#!/usr/bin/ruby -I. -I../../lib

require 'DemoClient'

host   = ARGV[1] || '127.0.0.1'
port   = ARGV[2] || '12345'
dir    = ARGV[3] || "%WINDIR%\\inf"
client = DemoClient.new(host, port).client

begin
	Dir.mkdir('/tmp/mirror_demo')
rescue
end

client.fs.dir.download('/tmp/mirror_demo', dir, true)
