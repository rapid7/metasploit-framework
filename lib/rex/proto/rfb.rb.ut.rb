#!/usr/bin/env ruby
# -*- coding: binary -*-
#
# $Id: $
#
# RFB protocol support
#
# @author Joshua J. Drake <jduck>
#
# Based on:
# vnc_auth_none contributed by Matteo Cantoni <goony[at]nothink.org>
# vnc_auth_login contributed by carstein <carstein.sec[at]gmail.com>
#

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'rex/socket'
require 'rex/proto/rfb'

sd = Rex::Socket::Tcp.create('PeerHost' => ENV["VNCHOST"], 'PeerPort' => Rex::Proto::RFB::DefaultPort)

v = Rex::Proto::RFB::Client.new(sd)
if not v.connect('password')
	$stderr.puts v.error
	exit(1)
end

loop {
	sret = select([sd],nil,nil,10)
	puts sret.inspect
	if sret and sret[0].include? sd
		buf = sd.sysread(8192)
		puts "read #{buf.length} bytes: #{buf.inspect}"
	end
}
