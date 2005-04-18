#!/usr/bin/ruby -I. -I../../lib

require 'DemoClient'

host    = ARGV[0] || '127.0.0.1'
port    = ARGV[1] || '12345'
src_dir = ARGV[2] || "%WINDIR%\\inf"
dst_dir = ARGV[3] || "/tmp/mirror_demo"
client  = DemoClient.new(host, port).client

begin
	Dir.mkdir(dst_dir)
rescue
end

client.fs.dir.download(dst_dir, src_dir, true)
