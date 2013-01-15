##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name' => 'SAPRouter Admin Request',
			'Description' => %q{
				Display the remote connection table from a SAPRouter.
				},
			'References' => [
					[ 'URL', 'http://labs.mwrinfosecurity.com/tools/2012/04/27/sap-metasploit-modules/' ],
					[ 'URL', 'http://help.sap.com/saphelp_nw70ehp3/helpdata/en/48/6c68b01d5a350ce10000000a42189d/content.htm'],
					[ 'URL', 'http://www.onapsis.com/research-free-solutions.php' ] # Bizsploit Opensource ERP Pentesting Framework
				],
			'Author' => [
				'nomnkee',
				'Mariano Nunez',    # Wrote Bizploit, helped on this module, very cool guy
				'Chris John Riley', # Testing
				'Ian de Villiers',  # Testing
				'Joris van de Vis'  # Testing
			],
			'License' => BSD_LICENSE
			)
		register_options(
			[
				Opt::RPORT(3299)
			], self.class)
	end

	def get_data(size, packet_len)
		info = ''
		1.upto(size) do |i|
			data = sock.recv(1)
			packet_len -= 1
			if data == "\x00"
				sock.recv(size - i)
				packet_len -= size - i
				return info, packet_len
				break
			else
				info << data
			end
		end
	end

	def run_host(ip)
		host_port = "#{ip}:#{datastore['RPORT']}"
		type = 'ROUTER_ADM'
		version = 0x26
		cmd = 0x2
		count = 0
		connected = true
		port = datastore['RPORT']
		source = ''
		destination = ''
		service = ''
		ni_packet = type + [0,version,cmd,0,0].pack("c*")
		ni_packet = [ni_packet.length].pack('N') << ni_packet
		saptbl = Msf::Ui::Console::Table.new(
			Msf::Ui::Console::Table::Style::Default,
				'Header' => "[SAP] SAProuter Connection Table for #{ip}",
				'Prefix' => "\n",
				'Postfix' => "\n",
				'Indent' => 1,
				'Columns' =>
					[
						"Source",
						"Destination",
						"Service"
					])
		begin
			connect
		rescue ::Rex::ConnectionRefused
			print_status("#{host_port} - Connection refused")
			connected = false
		rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error
			print_status("#{host_port} - Connection timeout")
			connected = false
		rescue ::Exception => e
			print_error("#{host_port} - Exception #{e.class} #{e} #{e.backtrace}")
			connected = false
		end
		if connected
			print_good("#{host_port} - Connected to saprouter")
			print_good("#{host_port} - Sending ROUTER_ADM packet info request")
			sock.put(ni_packet)
			packet_len = sock.read(4).unpack('H*')[0].to_i 16
			print_good("#{host_port} - Got INFO response")
			while packet_len !=0
				count += 1
				case count
				when 1
					if packet_len > 150
						sock.recv(150)
						packet_len -= 150
						source, packet_len = get_data(46,packet_len)
						destination, packet_len = get_data(46,packet_len)
						service, packet_len = get_data(30,packet_len)
						sock.recv(2)
						packet_len -= 2
						saptbl << [source, destination, service]
						while packet_len > 0
							sock.recv(13)
							packet_len -= 13
							source, packet_len = get_data(46,packet_len)
							destination, packet_len = get_data(46,packet_len)
							service, packet_len = get_data(30,packet_len)
							term = sock.recv(2)
							packet_len -= 2
							saptbl << [source, destination, service]
						end
						packet_len = sock.recv(4).unpack('H*')[0].to_i 16
					else
						print_error("#{host_port} - No connected clients")
						sock.recv(packet_len)
						packet_len = sock.recv(4).unpack('H*')[0].to_i 16
					end
				when 2
					data = sock.recv(packet_len)
					packet_len -= packet_len
					packet_len = sock.recv(4).unpack('H*')[0].to_i 16
				when 3
					clients = sock.recv(packet_len)
					packet_len -= packet_len
					packet_len = sock.recv(4).unpack('H*')[0].to_i 16
				when 4
					pwd = sock.recv(packet_len)
					print_good(pwd)
					packet_len -= packet_len
					packet_len = sock.recv(4).unpack('H*')[0].to_i 16
				when 5
					routtab = sock.recv(packet_len)
					print_good(routtab)
					packet_len -= packet_len
					packet_len = sock.recv(4).unpack('H*')[0].to_i 16
				end
				if packet_len == 0
					break
				end
			end
			disconnect
		# TODO: This data should be saved somewhere. A note on the host would be nice.
		print(saptbl.to_s)
		end
	end
end
