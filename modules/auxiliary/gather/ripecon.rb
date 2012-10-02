##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
# http://metasploit.com/
##

require 'msf/core'
require 'rexml/document'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name' => 'RIPEcon - Collect info from RIPE Register',
			'Version' => '$Revision$',
			'Description' => %q{
				This module attempt to gather informations from pubblic Internet registry
				helping the tester in the reconnaissance phase. Please review and agree
				with terms and conditions before using this module.
				(http://www.ripe.net/data-tools/support/documentation/terms)
				},

			'Author' =>
				[
					'Cristiano Maruti <cmaruti[at]gmail.com>'
				],

			'References' =>
				[
					['URL', 'http://www.ripe.net/data-tools/developer-documentation']
				],

			'License' => MSF_LICENSE
		)

		register_options([
			OptString.new('RIPE-GRSSEARCH-URI', [true, 'Path to the RIPE webservice', '/whois/grs-search']),
			OptString.new('RIPE-SEARCH-URI', [true, 'Path to the RIPE GRS webservice', '/whois/search']),
			OptString.new('KEYWORD', [true, 'Keyword you want to search for (ex. Microsoft, Google)']),
			OptString.new('OUTFILE', [false, "A filename to store the results of the module"]),
			OptString.new('RHOST', [true, 'The IP address of the RIPE apps server' , '193.0.6.142']),
			OptString.new('VHOST', [true, 'The host name runnning the RIPE webservice', 'apps.db.ripe.net']),
			OptInt.new('RPORT', [true, "Default remote port", 443])
		], self.class)

		register_advanced_options([
			OptBool.new('SSL', [true, "Negotiate SSL connection", true])
		], self.class)
	end

	def ripe_ws_url
		proto = "http"
		if rport == 443 or ssl
			proto = "https"
		end
		"#{proto}://#{vhost}:#{rport}"
	end

	def save_output(data)
		f = ::File.open(datastore['OUTFILE'], "wb")
		f.write(data)
		f.close
		print_status("Save results in #{datastore['OUTFILE']}")
	end

	def get_ripe_sources()

		payload = "#{ripe_ws_url}/whois/sources.xml"

		res = send_request_raw({
			'method' => 'GET',
			'uri' => payload,
			'SSL' => true
		}, 20)

		if(res)
			begin
				source = "#{ripe_ws_url}#{datastore['RIPE-SEARCH-URI']}?"
				source_grs = "#{ripe_ws_url}#{datastore['RIPE-GRSSEARCH-URI']}?"

				xml_source = REXML::Document.new(res.body)
				xml_source.elements.each("whois-resources/sources/source") do |element|
					source << "source=#{element.attributes["id"]}&"
				end
				# just to understand why afrinic sometimes doesn't work...
				# source = "#{ripe_ws_url}#{datastore['RIPE-SEARCH-URI']}?source=ripe&"

				xml_source_grs = REXML::Document.new(res.body)
				xml_source_grs.elements.each("whois-resources/grs-sources/source") do |element|
					source_grs << "source=#{element.attributes["id"]}&"
				end

				rescue REXML::ParseException => e
					print_error("Got an invalid XML response")
					vprint_line(e.message)
					return nil, nil
			end
			return source, source_grs
		else
			print_error("#{ripe_ws_url} - get_sources: Failed to connect")
		end

	end

	def do_search(keyword, query)
		# Save the results to this table
		tbl = Rex::Ui::Text::Table.new(
			'Header'  => 'Query Results',
			'Indent'  => 1,
			'Columns' => ['Name', 'Value'],
			'SortIndex' => -1
		)

		if query.nil?
			return
		end

		attribute = ['inetnum', 'netname', 'descr', 'country']

		res = send_request_cgi({
			'method' => 'GET',
			'uri' => "#{query}query-string=#{Rex::Text.uri_encode(datastore['KEYWORD'])}",
			'SSL' => true,
		}, 20)

		if(res and not res.body.match("Connection reset"))
			begin
				xml_source = REXML::Document.new(res.body)
				xml_source.elements.each("whois-resources/objects/object/attributes/attribute") do |detail|
					tbl << ["#{detail.attributes["name"]}", "#{detail.attributes["value"]}"] if attribute.include?(detail.attributes["name"])
				end

				#Show data and maybe save it if needed
				print_line("\n#{tbl.to_s}")
				save_output(tbl.to_s) if not datastore['OUTFILE'].nil?

			rescue REXML::ParseException => e
				print_error("Invalid XML response")
				vprint_line(e.message)
			end
		else
			print_error("#{query} - Failed to connect or invalid response")
		end
	end

	def run()

		begin
			print_status("RIPEcon: Retrieving sources...")
			std, grs = get_ripe_sources()
			print_status("Standard search results:")
			do_search(datastore['KEYWORD'], std)
			print_status("GRS search result:")
			do_search(datastore['KEYWORD'], grs)

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		rescue ::OpenSSL::SSL::SSLError => e
			return if(e.to_s.match(/^SSL_connect /) ) # strange errors / exception if SSL connection aborted
		end
	end
end
