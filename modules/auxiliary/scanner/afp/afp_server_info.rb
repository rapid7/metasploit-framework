##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	include Msf::Exploit::Remote::Tcp

	def initialize(info={})
		super(update_info(info,
			'Name'         => 'AFP Info Fatcher',
			'Description'  => %q{
				This module fetch AFP server information.
			},
			'References'     =>
				[
					[ 'URL', 'https://developer.apple.com/library/mac/#documentation/Networking/Reference/AFP_Reference/Reference/reference.html' ]
				],
			'Author'       => [ 'Gregory Man <man.gregory[at]gmail.com>' ],
			'License'      => MSF_LICENSE
		))

		register_options(
			[
				Opt::RPORT(548)
			], self.class)

		deregister_options('RHOST')
	end

	def run_host(ip)
		print_status("Scanning IP: #{ip.to_s}")
		begin
			connect
			get_server_info
		rescue ::Timeout::Error
		rescue ::Interrupt
			raise $!
		rescue ::Rex::ConnectionError, ::IOError, ::Errno::ECONNRESET, ::Errno::ENOPROTOOPT
		rescue ::Exception
			print_error("#{rhost}:#{rport} #{$!.class} #{$!} #{$!.backtrace}")
		ensure
			disconnect
		end
	end

	def get_server_info
		packet =  "\00"    # Flag: Request
		packet << "\x03"   # Command: FPGetSrvrInfo
		packet << "\x01\x03" # requestID
		packet << "\x00\x00\x00\x00" #Data offset
		packet << "\x00\x00\x00\x00" #Length
		packet << "\x00\x00\x00\x00" #Reserved

		sock.put(packet)
		response = sock.recv(1024)
		parse_response(response)
	end

	def parse_response(response)
		flags = response[0]
		command = response[1]
		request_id = response[2..3]
		error_code = response[4..7]
		length = response[8..11]
		reserved = response[12..15]

		body = response[16..length.unpack('N').first + 15]
		raise "Invalid packet length" if body.length != length.unpack('N').first

		machine_type_offset = body[0..1]
		version_count_offset = body[2..3]
		uam_count_offset = body[4..5]
		icon_offset = body[6..7]
		flags = body[8..9]
		server_name_length = body[10]

		server_name = read_pascal_string(body, 10)

		pos = 10 + server_name_length + 1

		server_signature_offset = body[pos..pos + 1]
		network_addresses_count_offset = body[pos + 2..pos + 3]
		directory_names_count_offset = body[pos + 4..pos + 5]
		utf8_server_name_offset = body[pos + 6..pos + 7]

		machine_type = read_pascal_string(body, machine_type_offset)
		versions = read_array(body, version_count_offset)
		uams = read_array(body, uam_count_offset)

		num_signature_offset = server_signature_offset.unpack('n').first
		server_signature = body[num_signature_offset..num_signature_offset + 15]

		directories = read_array(body, directory_names_count_offset)
		utf8_server_name = read_utf8_pascal_string(body, utf8_server_name_offset)

		parsed_flags = parse_flags(flags)
		network_addresses = read_array(body, network_addresses_count_offset, true)
		parsed_network_addresses = parse_network_addresses(network_addresses)

		#report
		report_info = "Server Flags: 0x#{flags.unpack('H*').first}\n" +
		format_flags_report(parsed_flags) +
		" Server Name: #{server_name.unpack('C*').pack('U*')} \n" +
		" Machine Type: #{machine_type} \n" +
		" AFP Versions: #{versions.join(', ')} \n" +
		" UAMs: #{uams.join(', ')}\n" +
		" Server Signature: #{server_signature.unpack("H*").first.to_s}\n" +
		" Server Network Address: \n" +
		format_addresses_report(parsed_network_addresses) +
		"  UTF8 Server Name: #{utf8_server_name}"

		print_status("#{rhost}:#{rport} APF:\n #{report_info}")
		report_note(:host => datastore['RHOST'],
			:proto => 'TCP',
			:port => datastore['RPORT'],
			:type => 'afp_server_info',
			:data => report_info)
	end

	def parse_network_addresses(network_addresses)
		parsed_addreses = []
		network_addresses.each do |address|
			case address[0]
			when 0 #Reserved
				next
			when 1 # Four-byte IP address
				parsed_addreses << IPAddr.ntop(address[1..4]).to_s
			when 2 # Four-byte IP address followed by a two-byte port number
				parsed_addreses <<  "#{IPAddr.ntop(address[1..4])}:#{address[5..6].unpack("n").first}"
			when 3 # DDP address (depricated)
				next
			when 4 # DNS name (maximum of 254 bytes)
				parsed_addreses << address[1..address.length - 2]
			when 5 # This functionality is deprecated.
				next
			when 6 # IPv6 address (16 bytes)
				parsed_addreses << "[#{IPAddr.ntop(address[1..16])}]"
			when 7 # IPv6 address (16 bytes) followed by a two-byte port number
				parsed_addreses << "[#{IPAddr.ntop(address[1..16])}]:#{address[17..18].unpack("n")}"
			else   # Something wrong?
				raise "Error pasing network addresses"
			end
		end
		return parsed_addreses
	end

	def parse_flags(flags)
		flags = flags.unpack("n").first.to_s(2)
		result = {}
		result['Super Client'] = flags[0,1] == '1' ? true : false
		result['UUIDs'] = flags[5,1] == '1' ? true : false
		result['UTF8 Server Name'] = flags[6,1] == '1' ? true : false
		result['Open Directory'] = flags[7,1] == '1' ? true : false
		result['Reconnect'] = flags[8,1] == '1' ? true : false
		result['Server Notifications'] = flags[9,1] == '1' ? true : false
		result['TCP/IP'] = flags[10,1] == '1' ? true : false
		result['Server Signature'] = flags[11,1] == '1' ? true : false
		result['ServerMessages'] = flags[12,1] == '1' ? true : false
		result['Password Saving Prohibited'] = flags[13,1] == '1' ? true : false
		result['Password Changing'] = flags[14,1] == '1' ? true : false
		result['Copy File'] = flags[5,1] == '1' ? true : false
		return result
	end

	def read_utf8_pascal_string(str, offset)
		offset = offset.unpack("n").first if offset.is_a?(String)
		length = str[offset..offset+1].unpack("n").first
		return str[offset + 2..offset + length + 1]
	end

	def read_pascal_string(str, offset)
		offset = offset.unpack("n").first if offset.is_a?(String)
		length = str[offset]
		return str[offset + 1..offset + length]
	end

	def read_array(str, offset, afp_network_address=false)
		offset = offset.unpack("n").first if offset.is_a?(String)
		size = str[offset]
		pos = offset + 1

		result = []
		size.times do
			result << read_pascal_string(str, pos)
			pos += str[pos]
			pos += 1 unless afp_network_address
		end
		return result
	end

	def format_flags_report(parsed_flags)
		report = ''
		parsed_flags.each do |flag, val|
			report << "    *  #{flag}: #{val.to_s} \n"
		end
		return report
	end

	def format_addresses_report(parsed_network_addresses)
		report = ''
		parsed_network_addresses.each do |val|
			report << "    *  #{val.to_s} \n"
		end
		return report
	end
end
