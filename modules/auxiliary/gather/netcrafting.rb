##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rexml/document'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name' => 'NetcRafting - a Netcraft domain Query Tool',
			'Version' => '$Revision$',
			'Description' => %q{
				This module identify domain that contain a given keyword using Netcraft
				search domain functionality. Please agree with terms and conditions prior
				using this module (http://news.netcraft.com/fair-use-copyright).
				},

			'Author' =>
				[
					'Cristiano Maruti <cmaruti[at]gmail.com>'
				],

			'References' =>
				[
					['URL', 'http://http://searchdns.netcraft.com']
				],

			'License' => MSF_LICENSE
		)

		register_options([
			OptString.new('RHOST', [true, 'The IP address of Netcraft searchdns  server', '194.72.238.150']),
			OptString.new('VHOST', [true, 'The host name runnning Netcraft searchdns tool', 'searchdns.netcraft.com']),
			OptString.new('OUTFILE', [false, "A filename to store the results of the module"]),
			OptString.new('KEYWORD', [true, 'Keyword you want to search for (ex. Microsoft, Google)']),
		], self.class)

	end

	def netcraft_url
		"http://#{datastore['VHOST']}:80"
	end

	def save_output(data)
		f = ::File.open(datastore['OUTFILE'], "wb")
		f.write(data)
		f.close
		print_status("Save results in #{datastore['OUTFILE']}")
	end

	def do_search_netcraft(keyword)

		payload = "#{netcraft_url}?restriction=site+contains&host=*#{Rex::Text.uri_encode(keyword)}*"
		#print_good("#{payload}")

		# Save the results to this table
		tbl = Rex::Ui::Text::Table.new(
			'Header'  => 'Query Results',
			'Indent'  => 1,
			'Columns' => ['Site', 'Netblock', 'OS'],
		)

		begin
			res = send_request_raw({
				'method' => 'GET',
				'uri' => payload
			}, 20)

			if(res)
				begin
					res.body.scan(/\/site_report\?url=http:\/\/(.+)"><img .+><\/a><\/td>\n<td>.+<\/td>\n<td>.+\/netblock\?q=[a-z0-9\-\.,]+">(.*)<\/a><\/td>\n<td>.+\/up\/graph\/\?host=.+">(.*)<\/a>/i) do |m|
						tbl << ["#{m[0]}", "#{m[1]}", "#{m[2]}"]
					end

					if not res.body.scan(/\/\?host=\*#{keyword}\*&.*&position=/i)[0].nil?
						payload = "#{netcraft_url}" << res.body.scan(/\/\?host=\*#{keyword}\*&.*&position=/i)[0]
					end

				rescue Exception => e
					print_error("Error retrieving details in the page body")
					vprint_line(e.message)
				end
			else
				print_error("Failed to connect to #{netcraft_url}")
			end

		end while (not res.body.scan(/<b>Next page<\/b>/i)[0].nil?)

		#Show data and maybe save it if needed
		print_line("\n#{tbl.to_s}")
		save_output(tbl.to_s) if not datastore['OUTFILE'].nil?
	end

	def run()

		begin
			print_status("NetcRafting results:")
			do_search_netcraft(datastore['KEYWORD'])

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end

	end

end
