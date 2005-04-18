#!/usr/bin/ruby -I. -I../../lib

require 'DemoClient'

host    = ARGV[0] || '127.0.0.1'
port    = ARGV[1] || '12345'
src_dir = ARGV[2] || "/tmp/mirror_src_demo"
dst_dir = ARGV[3] || "c:\\personal\\temp\\dst_mirror"
client  = DemoClient.new(host, port).client

begin
	client.fs.dir.mkdir(dst_dir)
rescue
end

client.fs.dir.upload(dst_dir, src_dir, true)
