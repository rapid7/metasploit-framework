##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'rexml/document'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'CorpWatch API Information',
			'Description'    => %q{
				This module interfaces with the CorpWatch API to get identification information
				for use with the corpwatch_info.rb module. The most important information is the CW_ID.
			},
			'Author'         => [ 'Brandon Perry' ],
			'Version'        => '$Revision: $',
			'References'     =>
				[
					[ 'URL', 'http://api.corpwatch.org/' ]
				]
		))

		register_options(
			[
				OptString.new('RHOST', [true, "CorpWatch API url", "api.corpwatch.org"]),
				OptString.new('COMPANY_NAME', [ true, "Search for companies with this name", ""]),
				OptString.new('YEAR', [ false, "Limit results to a specific year", ""]),
				OptString.new('LIMIT', [ true, "Limit the number of results returned", "5"]),
				OptString.new('API_KEY', [ false, "Use this API key when getting the data", ""]),
			], self.class)
	end

	def run
		
		uri = "/"
			
		uri << (datastore['YEAR'] + "/") if datastore['YEAR'] != ""
		uri << ("companies.xml?company_name=" + datastore['COMPANY_NAME'])
		uri << ("&limit=" + datastore['LIMIT'])
		uri << ("&key=" + datastore['API_KEY']) if datastore['API_KEY'] != ""

		header = { 'User-Agent' => "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}
	
                res = send_request_raw({
                        'uri'           => uri,
                        'method'        => 'GET',
                        'headers'       => header
                }, 25)
                
                doc = REXML::Document.new(res.body)

		root = doc.root
		
		results = root.get_elements("result")[0]

		if (results == nil)
			print_status("No results returned")
			return	
		end

		results = results.get_elements("companies")[0]

		results.elements.each { |e|

			cwid = grab_text(e, "cw_id")
			company_name = grab_text(e, "company_name")
			address = grab_text(e, "raw_address")
			sector = grab_text(e, "sector_name")
			industry = grab_text(e, "industry_name")

			puts "\n\n"
			print_status("Company Information\n---------------------------------")
			print_status("CorpWatch (cw) ID): " + cwid)
			print_status("Company Name: " + company_name)
			print_status("Address: " + address)	
			print_status("Sector: " + sector)
			print_status("Industry: " + industry)
			
			#report_note(:data => [cwid, company_name, address, sector, industry])
		}
		
	
	end

	def grab_text(e, name)
		(e.get_elements(name) && e.get_elements(name)[0] && 
           	e.get_elements(name)[0].get_text ) ? 
            	e.get_elements(name)[0].get_text.to_s  : ""
	end

end
