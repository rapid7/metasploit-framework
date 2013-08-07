##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/exploit/smb/psexec'
require 'rex/registry'
require 'fileutils'
#require 'msf/core/exploit/psexec'

class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::DCERPC
	include Msf::Exploit::Remote::SMB
	include Msf::Exploit::Remote::SMB::Psexec
	include Msf::Exploit::Remote::SMB::Authenticated
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	# Aliases for common classes
	SIMPLE = Rex::Proto::SMB::SimpleClient
	XCEPT = Rex::Proto::SMB::Exceptions
	CONST = Rex::Proto::SMB::Constants


	def initialize
		super(
			'Name'        => 'SMB - Check Local Admin',
			'Description' => %Q{
				This module will check if a set of credentials has local admin
				or not by authenticating over SMB and then binding to ADMIN$.
			},
			'Author'      =>
				[
					'Royce Davis <rdavis[at]accuvant.com>',    # @R3dy__
				],
			'References'  => [
				['URL', 'http://www.pentestgeek.com']
			],
			'License'     => MSF_LICENSE
		)
		register_options([
			OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'ADMIN$']),
			OptString.new('RPORT', [true, 'The Target port', 445]),
		], self.class)
		deregister_options('RHOST')
	end


	def peer
		return "#{rhost}:#{rport}"
	end


	# This is the main controller function
	def run_host(ip)
		smbshare = datastore['SMBSHARE']
		if connect
			begin
				smb_login
			rescue StandardError => autherror
				vprint_error("#{peer} - #{autherror}")
				return
			end
			if check_admin(ip, smbshare)
				print_good("#{peer} SUCCESS.  User has local admin.  #{datastore['SMBDomain']}\\#{datastore['SMBUser']} #{datastore['SMBPass']} - #{smb_peer_os}")
				report_creds(datastore['SMBDomain'],datastore['SMBUser'],datastore['SMBPass'],true)
			end
			disconnect
		end
	end

	def check_admin(host, share)
		begin
			if simple.connect("\\\\#{host}\\#{share}")
				simple.disconnect("\\\\#{host}\\#{share}")
				return true
			end
		rescue StandardError => checkerror
			vprint_error("#{peer} - Host not admin #{checkerror}")
			return false
		end
	end
	
	def report_creds(domain,user,pass,active)
		login_name = ""
		login_name = "#{domain}\\#{user}"
		report_hash = {
			:host	=> rhost,
			:port   => datastore['RPORT'],
			:sname	=> 'smb',
			:user 	=> login_name,
			:pass   => pass,
			:source_type => "user_supplied",
			:active => active,
			:admin => "yes"
		}
		if pass =~ /[0-9a-fA-F]{32}:[0-9a-fA-F]{32}/
			report_hash.merge!({:type => 'smb_hash'})
		else
			report_hash.merge!({:type => 'password'})
		end
		report_auth_info(report_hash)
	end
end
