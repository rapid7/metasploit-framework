#!/usr/bin/ruby -I. -I../../lib

require 'DemoClient'

host   = ARGV[0] || '127.0.0.1'
port   = ARGV[1] || '12345'
client = DemoClient.new(host, port).client

pid = client.sys.process['calc.exe']

puts "before migrate: my pid is #{client.sys.process.getpid}"

client.core.migrate(pid)

puts "after migrate: my pid is #{client.sys.process.getpid}"

while (1)
	select nil, nil, nil, 5
end
