##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'rexml/document'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'CorpWatch API Information',
			'Description'    => %q{
				This module interfaces with the CorpWatch API to get publicly available
				info for a given company.
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
				OptString.new('RHOST', [true, "URL for CorpWatchAPI", "api.corpwatch.org"]),
				OptString.new('CW_ID', [ true, "The CorpWatch ID of the company", ""]),
				OptString.new('YEAR', [ false, "Year to look up", ""]),
				OptBool.new('GET_LOCATIONS', [ false, "Get locations for company", true]),
				OptBool.new('GET_NAMES', [ false, "Get all registered names ofr the company", true]),
				OptBool.new('GET_FILINGS', [ false, "Get all filings", false ]),
				OptBool.new('GET_CHILDREN', [false, "Get children companies", true]),
				OptInt.new('CHILD_LIMIT', [false, "Set limit to how many children we can get", 5]),
				OptBool.new('GET_HISTORY', [false, "Get company history", false])
			], self.class)
	end

	def run
		url = "api.corpwatch.org"
		uri = "/"
		header = { 'User-Agent' => "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}		

		uri << (datastore['YEAR']) if datastore['YEAR'] != ""
		
		uri << ("/companies/" + datastore['CW_ID'])

		res = send_request_raw({
			'uri' 		=> uri + ".xml",
			'method'	=> 'GET',
			'headers'	=> header
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
			cik = grab_text(e, "cik")
			name = grab_text(e, "company_name")
			irsno = grab_text(e, "irs_number")
			sic_code = grab_text(e, "sic_code")
			sector = grab_text(e, "sector_name")
			source = grab_text(e, "source_type")
			address = grab_text(e, "raw_address")
			country = grab_text(e, "country_code")
			subdiv = grab_text(e, "subdiv_code")
			top_parent = grab_text(e, "top_parent_id")
			num_parents = grab_text(e, "num_parents")
			num_children = grab_text(e, "num_children")
			max_year = grab_text(e, "max_year")
			min_year = grab_text(e, "min_year")

			print_status("Basic Information\n--------------------")
			print_status("CorpWatch ID: " + cwid)
			print_status("Central Index Key (CIK): " + cik)
			print_status("Full Name: " + name)
			print_status("IRS Number: " + irsno)
			print_status("SIC Code: " + sic_code)
			print_status("Sector: " + sector)
			print_status("Source Type: " + source)

			puts "\n"
			print_status("Address and Location Information\n-----------------------------")
			print_status("Full Address: " + address)
			print_status("Country Code: " + country)
			print_status("Subdivision: " + subdiv)

			puts "\n"
			print_status("Parent and Children Information\n---------------------------")
			print_status("Top Parent ID: " + top_parent)
			print_status("Number of parent companies: " + num_parents)
			print_status("Number of child companies: " + num_children)
			print_status("Max lookup year: " + max_year)
			print_status("Min lookup year: " + min_year) 
			
		}

		

		if datastore['GET_LOCATIONS'] == true

                	res = send_request_raw({
                        	'uri'           => uri + "/locations.xml",
                        	'method'        => 'GET',
                	        'headers'       => header
        	        }, 25)
                
	                doc = REXML::Document.new(res.body)

			root = doc.root
			
			results = root.get_elements("result")[0]

			if (results == nil)
				print_status("No results returned")
				
			else

				results = results.get_elements("locations")[0]


				results.elements.each { |e|
					cwid = grab_text(e, "cw_id")
					country_code = grab_text(e, "country_code")
					subdiv_code = grab_text(e, "subdiv_code")
					type = grab_text(e, "type")
					full_address = grab_text(e, "raw_address")
					street1 = grab_text(e, "street_1")
					street2 = grab_text(e, "street_2")
					city = grab_text(e, "city")
					state = grab_text(e, "state")
					zip = grab_text(e, "postal_code")
					date_valid = grab_text(e, "date")
					max_year = grab_text(e, "max_year")
					min_year = grab_text(e, "min_year")
				
					puts "\n\n"
					print_status("Detailed Location Information\n----------------------------------")
					print_status("Country Code: " + country_code)
					print_status("Subdivision: " + subdiv_code)
					print_status("Residential/Business address: " + type)
					print_status("Full Address: " + full_address)
					print_status("Street 1: " + street1)
					print_status("Street 2: " + street2)
					print_status("City: " + city) 
					print_status("State:" + state)
					print_status("Postal Code: " + zip)
					print_status("Date address was valid: " + date_valid)
					print_status("Max lookup year: " + max_year)
					print_status("Min lookup year: " + min_year)
				}

			end
		end

		if datastore['GET_NAMES'] == true

                	res = send_request_raw({
                	        'uri'           => uri + "/names.xml",
                	        'method'        => 'GET',
                	        'headers'       => header
                	}, 25)
                	
                	doc = REXML::Document.new(res.body)
			
			root = doc.root

			results = root.get_elements("result")[0]


			if (results == nil)
				print_status("No results returned")
			
			else
	
				results = results.get_elements("names")[0]

				results.elements.each { |e|
					name = grab_text(e, "company_name")
					source = grab_text(e, "source")
					date = grab_text(e, "date")
					max_year = grab_text(e, "max_year")
					min_year = grab_text(e, "min_year")
			

					puts "\n\n"
					print_status("Detailed Name Information\n---------------------------")
					print_status("Name: " + name)
					print_status("Source: " + source)
					print_status("Date valid: " + date)
					print_status("Max lookup year: " + max_year)
					print_status("Min lookup year: " + min_year)	
				}

			end
		end

		if datastore['GET_FILINGS'] == true

                	res = send_request_raw({
                	        'uri'           => uri + "/filings.xml",
                	        'method'        => 'GET',
                	        'headers'       => header
                	}, 25)
                	
                	doc = REXML::Document.new(res.body)
			root = doc.root
			
			results = root.get_elements("result")[0]

			if results == nil
				print_status("No results returned")
			
			else

			results = results.get_elements("filings")[0]

			if results == nil
				print_status("No filings found")
				
			else

				results.elements.each { |e|
					cik = grab_text(e, "cik")
					year_filed = grab_text(e, "year")
					quarter_filed = grab_text(e, "quarter")
					report_period = grab_text(e, "period_of_report")
					filing_date = grab_text(e, "filing_date")
					form10k = grab_text(e, "form_10K_url")
					sec21 = grab_text(e, "sec_21_url")
					is_filer = grab_text(e, "company_is_filer")

					puts "\n\n"
					print_status("Detailed Filing Information\n---------------------")
					print_status("Central Index Key: " + cik)
					print_status("Year filed: " + year_filed)
					print_status("Quarter Filed: " + quarter_filed)
					print_status("Report Period: " + report_period)
					print_status("Filing Date: " + filing_date)
					print_status("10K Filing Form: " + form10k)
					print_status("SEC 21 Form: " + sec21)
					print_status("Company is active filer: " + (is_filer == "1" ? "true" : "false")) 
			
				}
			end
			end	
		end

		if datastore['GET_CHILDREN']
			child_uri = (uri + "/children.xml")

			if datastore['CHILD_LIMIT'] != nil
				child_uri << "?limit=#{datastore['CHILD_LIMIT']}"
				print_status("Limiting children results to 5")
			end

	                res = send_request_raw({
	                        'uri'           => child_uri,
	                        'method'        => 'GET',
	                        'headers'       => header
	                }, 25)
	                
	                doc = REXML::Document.new(res.body)

			root = doc.root

			results = root.get_elements("result")[0]

			if results == nil
				print_status("No results were returned.")
				
			else

				results = results.get_elements("companies")[0]

				if results == nil
					print_status("No results returned")
				else

					results.elements.each { |e|
				        cwid = grab_text(e, "cw_id")
				        cik = grab_text(e, "cik")
				        name = grab_text(e, "company_name")
				        irsno = grab_text(e, "irs_number")
				        sic_code = grab_text(e, "sic_code")
				        sector = grab_text(e, "sector_name")
				        source = grab_text(e, "source_type")
				        address = grab_text(e, "raw_address")
				        country = grab_text(e, "country_code")
				        subdiv = grab_text(e, "subdiv_code")
				        top_parent = grab_text(e, "top_parent_id")
				        num_parents = grab_text(e, "num_parents")
				        num_children = grab_text(e, "num_children")
				        max_year = grab_text(e, "max_year")
				        min_year = grab_text(e, "min_year")
			
					puts "\n\n"
				        print_status("Child Information\n--------------------")
				        print_status("CorpWatch ID: " + cwid)
				        print_status("Central Index Key (CIK): " + cik)
				        print_status("Full Name: " + name)
				        print_status("IRS Number: " + irsno)
				        print_status("SIC Code: " + sic_code)
				        print_status("Sector: " + sector)
				        print_status("Source Type: " + source)

				        puts "\n"
				        print_status("Address and Location Information\n-----------------------------")
				        print_status("Full Address: " + address)
				        print_status("Country Code: " + country)
				        print_status("Subdivision: " + subdiv)

				        puts "\n"
				        print_status("Parent and Children Information\n---------------------------")
				        print_status("Top Parent ID: " + top_parent)
				        print_status("Number of parent companies: " + num_parents)
				        print_status("Number of child companies: " + num_children)
				        print_status("Max lookup year: " + max_year)
				        print_status("Min lookup year: " + min_year)

					}
				end

			end				
		end
	
		if datastore['GET_HISTORY'] == true
			response, data = client.get2(uri + "/history.xml", header)
			
			doc = Document.new(data)
	
			root = doc.root

			results = root.get_elements("result")[0]

			if results == nil
				print_status("No results returned.")
				
			else

				results = results.get_elements("companies")[0]

				results.elements.each { |e|
					cwid = grab_text(e, "cw_id")
					cik = grab_text(e, "cik")
					irsno = grab_text(e, "irs_number")
					sic_code = grab_text(e, "sic_code")
					industry = grab_text(e, "industry_name")
					sector = grab_text(e, "sector_name")
					sic_sector = grab_text(e, "sic_sector")
					source = grab_text(e, "source_type")
					address = grab_text(e, "raw_address")
					country_code = grab_text(e, "country_code")
					subdiv_code = grab_text(e, "subdiv_code")
					top_parent = grab_text(e, "top_parent_id")
					num_parents = grab_text(e, "num_parents")
					num_children = grab_text(e, "num_children")
					max_year = grab_text(e, "max_year")
					min_year = grab_text(e, "min_year")
					history_year = grab_text(e, "year")


					puts "\n\n"
					print_status("Company History for year #{history_year}\n--------------------------------")
					print_status("CorpWatch ID: " + cwid)
					print_status("Central Index Key: "  + cik)
					print_status("IRS number: " + irsno)
					print_status("SIC Code: " + sic_code)
					print_status("Industry: " + industry)
					print_status("Sector: " + sector)
					print_status("SIC Sector: " + sic_sector)
					print_status("Source: " + source)
					print_status("Address: " + address)
					print_status("Country: " + country_code)
					print_status("Subdivision: " + subdiv_code)
					print_status("Top Parent ID: " + top_parent)
					print_status("Number of parents: " + num_parents)
					print_status("Number of children: " + num_children)
					print_status("Max lookup year: " + max_year)
					print_status("Min lookup year: " + min_year)
				}

			end
		end

	end

	def grab_text(e, name)
		(e.get_elements(name) && e.get_elements(name)[0] &&
		e.get_elements(name)[0].get_text ) ?
		e.get_elements(name)[0].get_text.to_s : ""
	end

end
