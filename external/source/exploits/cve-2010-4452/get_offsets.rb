#!/usr/bin/env ruby

dat = nil
dat = File.open(ARGV[0], 'rb') { |fd| fd.read }
if dat 
	puts "config_off = 0x%x" % dat.index("\x00\x08CONFIGZZ")
	puts "cn_off = 0x%x" % dat.index("\x00\x07AppletX")
else
	"No data?!"
end

