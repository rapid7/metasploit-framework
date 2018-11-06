# $Id: http.rb,v 1.2 2006/10/05 01:36:52 koheik Exp $
require 'socket'
$:.unshift(File.dirname(__FILE__) + '/../lib')
require 'net/ntlm'

$user = nil
$passwd = nil

$host = "www"
$port = 80

def header(f, host)
	f.print "GET / HTTP/1.1\r\n"
	f.print "Host: #{host}\r\n"
	f.print "Keep-Alive: 300\r\n"
	f.print "Connection: keep-alive\r\n"
end

def main

	s = TCPSocket.new($host, $port)

	# client -> server
	t1 = Net::NTLM::Message::Type1.new()
	header(s, $host)
	s.print "Authorization: NTLM " + t1.encode64 + "\r\n"
	s.print "\r\n"

	# server -> client
	length = 0
	while(line = s.gets)
		
		if /^WWW-Authenticate: (NTLM|Negotiate) (.+)\r\n/ =~ line
			msg = $2
		end
		
		if /^Content-Length: (\d+)\r\n/ =~ line
			length = $1.to_i
		end
		if /^\r\n/ =~ line
			if length > 0
				cont = s.read(length)
			end
			break
		end
	end
	t2 = Net::NTLM::Message.decode64(msg)
	
	unless $user and $passwd
		target = t2.target_name
		target = Net::NTLM::EncodeUtil.decode_utf16le(target) if t2.has_flag?(:UNICODE)
		puts "Target: #{target}"
		print "User name: "
		($user = $stdin.readline).chomp!
		print "Password: "
		($passwd = $stdin.readline).chomp!
	end
	
	# client -> server, again
	t3 = t2.response({:user => $user, :password => $passwd}, {:ntlmv2 => true})
	header(s, $host)
	s.print "Authorization: NTLM " + t3.encode64 + "\r\n"
	s.print "\r\n"
	
	# server -> client
	length = 0
	while(line = s.gets)
		
		if /^WWW-Authenticate: (NTLM|Negotiate) (.+)\r\n/ =~ line
			msg = $2
		end
		
		if /^Content-Length: (\d+)\r\n/ =~ line
			length = $1.to_i
		end
		if /^\r\n/ =~ line
			if length > 0
				p cont = s.read(length)
			end
			break
		end
	end
	s.close
end

main
