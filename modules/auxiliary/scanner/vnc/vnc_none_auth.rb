##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	
	def initialize
		super(
			'Name'        => 'VNC Authentication None Detection',
			'Version'     => '$Revision$',
			'Description' => 'Detect VNC server with empty password.',
			'References'  =>
				[
					['URL', 'http://en.wikipedia.org/wiki/RFB'],
					['URL', 'http://en.wikipedia.org/wiki/Vnc'],
				],
			'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			Opt::RPORT(5900),
		], self.class)
	end

	def run_host(target_host)
		
		connect

		begin
			banner = sock.get_once(50,1)

			# RFB Protocol Version 3.3 (1998-01) 
			# RFB Protocol Version 3.7 (2003-08) 
			# RFB Protocol Version 3.8 (2007-06) 
			if (banner and banner =~ /RFB 003\.003|RFB 003\.007|RFB 003\.008/)
				ver,msg = (banner.split(/\n/))

				print_status("#{target_host}:#{rport}, VNC server protocol version : #{ver}")

				if msg
					if (msg =~ /Too many security failures/)
						msg = msg + ". " + "Wait for a moment!"
					end
					print_status("#{target_host}:#{rport}, VNC server warning messages : \"#{msg}\"") 
				else	
					# send VNC client protocol version
					cver = ver + "\x0a"
					sock.put(cver)
			
					# first byte is number of security types
					num_types = sock.get_once(1).unpack("C").first
					if (num_types == 0)
						msg_len = sock.get_once(4).unpack("N").first
						raise RunTimeError.new("Server error: #{sock.get_once(msg_len)}")
					end
					types = sock.get_once(num_types).unpack("C*")

					# Security types
					#  1 : No authentication, no encryption
					#  2 : Standard VNC authentication
					# 16 : Tight (tightvncserver)
					# 17 : Ultra
					# 18 : TLS
					
					sec_type = []
					if types
						sec_type << "None"   if (types.include? 1)
						sec_type << "VNC"    if (types.include? 2)
						sec_type << "Tight"  if (types.include? 16)  
						sec_type << "Ultra"  if (types.include? 17)
						sec_type << "TLS"    if (types.include? 18)  
						print_status("#{target_host}:#{rport}, VNC server security types supported : #{sec_type.join(",")}")
						if (types.include? 1)
							print_status("#{target_host}:#{rport}, VNC server security types includes None, free access!")
						end
					else
						print_error("#{target_host}:#{rport}, failed to parse security types")
					end
				end
			elsif banner
				print_status("#{target_host}:#{rport}, VNC server protocol version : \"#{banner.chomp}\", not supported!")
			else
				print_error("#{target_host}:#{rport}, failed to retreive banner")
			end

		ensure
			disconnect
		end
	end
end
