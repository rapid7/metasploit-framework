#!/usr/bin/ruby -I. -I../../lib

require 'DemoClient'

HTML_FILE = "demo1.html"

host   = ARGV[1] || '127.0.0.1'
port   = ARGV[2] || '12345'
client = DemoClient.new(host, port).client

client.fs.file.upload('%TEMP%', HTML_FILE)

client.sys.process.execute('cmd /C "explorer %TEMP%\demo1.html"')
