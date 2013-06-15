# -*- coding: binary -*-
#Viproy SIP Library
#Author : Fatih Ozavci - viproy.com/fozavci
#Github : github.com/fozavci/viproy-voipkit

require 'rex/proto/sip'

module Msf

module Auxiliary::SIP
	attr_accessor :listen_addr, :listen_port, :context
	attr_accessor :sock, :thread, :dest_addr, :dest_port
	attr_accessor :prxclient_port, :prxclient_ip, :client_port, :client_ip 
	attr_accessor :prxserver_port, :prxserver_ip, :server_port, :server_ip 

	def start_sipsrv(listen_port = 5060, listen_addr = '0.0.0.0', dest_port = 5060, dest_addr = nil, context = {})
		raise ::Rex::ArgumentError, 'Destination IP Address Required' if dest_addr == nil 
		@mode = "server"
		
		self.listen_addr = listen_addr
		self.listen_port = listen_port
		self.dest_addr = dest_addr
		self.dest_port = dest_port
		self.context = context
		self.sock = nil	

		print_status("Starting SIP Socket on #{listen_addr}:#{listen_port}") if datastore['VERBOSE']
		@sip = Rex::Proto::SIP::Socket.new(listen_port,listen_addr,dest_port,dest_addr,context)
	end


	def start_sipprx(prxclient_port = 5080, prxclient_ip = '0.0.0.0', client_port = 5060, client_ip = nil, prxserver_port = 5081, prxserver_ip = '0.0.0.0', server_port = 5060, server_ip = nil, context = {})
		raise ::Rex::ArgumentError, 'Server and Client IP Addresses Required' if client_ip.nil? or server_ip.nil?
		@mode = "proxy"
		
		self.prxclient_ip = prxclient_ip
		self.prxclient_port = prxclient_port
		self.prxserver_ip = prxserver_ip
		self.prxserver_port = prxserver_port
		self.client_ip = client_ip
		self.client_port = client_port
		self.server_ip = server_ip
		self.server_port = server_port
		self.context = context
		self.sock = nil	
		@logfile = nil

		@replace_portiptable={}
		
		@replace_portiptable["clt"]={
			"#{prxclient_ip}:#{prxclient_port}" => "#{server_ip}:#{server_port}",
			"@#{prxclient_ip}>" => "@#{server_ip}>",
			":#{prxclient_ip}" => ":#{server_ip}",
			"#{client_ip}:#{client_port}" => "#{prxserver_ip}:#{prxserver_port}",
			"@#{client_ip}>" => "@#{prxserver_ip}>",
			":#{client_ip}>" => ":#{prxserver_ip}>",
		}

		@replace_portiptable["srv"]={
			"#{prxserver_ip}:#{prxserver_port}" => "#{client_ip}:#{client_port}",
			"@#{prxserver_ip}>" => "@#{client_ip}>",
			":#{prxserver_ip}>" => ":#{client_ip}>",
			"#{server_ip}:#{server_port}" => "#{prxclient_ip}:#{prxclient_port}",
			":#{server_ip}>" => ":#{prxclient_ip}>",
		}


		print_good("Starting Proxy Service....")
		print_good("Settings For Client => #{prxclient_ip}:#{prxclient_port}")
		print_good("Settings For Server => #{prxserver_ip}:#{prxserver_port}\n")
		@sipprx1 = Rex::Proto::SIP::Socket.new(prxclient_port,prxclient_ip,client_port,client_ip,context)
		@sipprx2 = Rex::Proto::SIP::Socket.new(prxserver_port,prxserver_ip,server_port,server_ip,context)
	end

	#
	# Start the SIPSocket Monitor
	# 
	def start_monitor
		case @mode
		when "server"
			self.thread = Rex::ThreadFactory.spawn("SIPServerMonitor", false) {
				monitor_socket(@sip)
			}
		when "proxy"
			self.thread = Rex::ThreadFactory.spawn("SIPServerMonitor", false) {
				monitor_socket(@sipprx1)
			}
			self.thread = Rex::ThreadFactory.spawn("SIPServerMonitor", false) {
				monitor_socket(@sipprx2)
			}
		else
			print_error("No Service Detected")
		end
	end

	def stop
		print_status("Stopping SIP Sockets...") 
		@sip.sock.close if not @sip.nil?
		@sipprx1.sock.close if not @sipprx1.nil?
		@sipprx2.sock.close if not @sipprx2.nil?
		@logfile.close if not @logfile.nil?
	end

	# removes any leading ipv6 stuff, such as ::ffff: as it breaks JtR
	# obtained from 'Patrik Karlsson <patrik[at]cqure.net>' sip capture module
	def sanitize_address(addr)
		if ( addr =~ /:/ )
			return addr.scan(/.*:(.*)/)[0][0]
		end
		return addr
	end

	#Auxiliary Module Should Replace This Function To Dispatch Requests 
	def dispatch_request(from,buf)
		ip=sanitize_address(from[0]).to_s
		port=from[1].to_s

		logwrite(buf,ip,port) if not @logfile.nil?

		case @mode
		when "server"
		when "proxy"
			if ip == client_ip and port == client_port.to_s
				prxredirect(@sipprx2,buf,ip,port,"clt")
			elsif  ip == server_ip and port == server_port.to_s
				prxredirect(@sipprx1,buf,ip,port,"srv")
			else
				print_error("Content from Unkown Location => "+ip+":"+port)
			end
		else
			print_status("Mode Error")
		end
	end

	def prxredirect(sipprx,buf,ip,port,type)
		#vprint_status("Content from "+ip+":"+port)
		buf=replace_port_ip(buf,type)
		if (buf =~ /^Authorization: Digest \s*(.*)$/i)	
			creds=$1
			req_type=buf.split(" ")[0]
			print_good("SIP Account Credentials : ")
			buf=buf.gsub("uri=\"sip:#{self.server_ip}\"","uri=\"sip:#{self.prxclient_ip}\"") 
			print_good(" request="+req_type)
			creds.split(", ").each do |c|
				print_good(" #{c.gsub("\"","")}")
			end
		end

		buf=replace_it(buf) if @replacement_table 
		logwrite(buf,ip,port,mod="MODIFIED")
		sipprx.send_rawdata(buf)
	end

	def replace_port_ip(data,type)
		@replace_portiptable[type].each do |r,c|
			#vprint_status("Type #{type} : Replace For"+r+"=>"+c)
			#vprint_status("Content is :\n"+data)	
			data.gsub!(r,c)
		end
		return data
	end

	def replace_it(data)
		@replacement_table.each do |r,c|
			data.gsub!(r,c)
		end
		return data
	end

 	def logwrite(buf,ip,port,mod="ORIGINAL")
			@logfile.write "#{mod}-------#{ip} : #{port}------------------\n"
			@logfile.write buf+"\n\n"
	end

	def set_replacefile(f)
		print_good("Replacement File is "+f.to_s+"\n")
		@replacement_table = {}
		contents=File.new(f, "r")
		contents.each do |line|
			next if line =~ /^#/
			t = line.split("\t")[0]
			r = Regexp.new t
			c = line.split("\t")[1..1000].join("\t").chop
			@replacement_table[r] = c
		end
	end

	def set_logfile(f)
		print_good("Log File is "+f.to_s+"\n")
		@logfile = File.new(f, "w")
	end


	#Monitor Socket
	def monitor_socket(s)
		while true
			rds = [s.sock]
			wds = []
			eds = [s.sock]
			r,w,e = ::IO.select(rds,wds,eds,1)
			if (r != nil and r[0] == s.sock)
				buf,host,port = s.sock.recvfrom()
				from = [host, port]
				dispatch_request(from, buf)
			end
		end
	end

	#
	# Sending Register
	# 
	def send_register(req_options={})  
		@sip.register(req_options)  
	end

	#
	# Converting Errors
	# 
	def convert_error(err)
		@sip.convert_error(err)
	end
	
	#
	# Sending Options
	#    
	def send_options(req_options={})        
		@sip.send_options(req_options)
	end

	#
	# Sending Subscribe
	#    
	def send_subscribe(req_options={})
		@sip.send_subscribe(req_options)
	end		

	#
	# Sending ACK
	#    
	def send_ack(req_options={})
		@sip.send_ack(req_options)
	end		

  	#
	# Sending Invite
	#    
	def send_invite(req_options={})
		@sip.send_invite(req_options)
	end

end

end
