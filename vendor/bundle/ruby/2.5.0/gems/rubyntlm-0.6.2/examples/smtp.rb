# $Id: smtp.rb,v 1.2 2006/10/05 01:36:52 koheik Exp $
require 'socket'
$:.unshift(File.dirname(__FILE__) + '/../lib')
require 'net/ntlm'

$user = nil
$passwd = nil

$host = "localhost"
$port = 25

$debug = true

def readline(f)
	(l = f.gets).chomp!
	puts "srv> " + l if $debug
	l
end

def writeline(f, str)
	puts "cli> " + str if $debug
	f.print str + "\r\n"
end

def main
	s = TCPSocket.new($host, $port)

	# greetings
	readline s
	writeline s, "EHLO #{$host}" 
	while(line = readline(s))
		login = true if /^250-AUTH=LOGIN/ =~ line
		ntlm = true if /^250-AUTH.+NTLM.*/ =~ line
		break if /^250 OK/ =~ line
	end
	unless ntlm and login
		raise RuntimeError, "it looks like the server doesn't support NTLM Login" 
	end
	
	# send Type1 Message
	t1 = Net::NTLM::Message::Type1.new()
	writeline s, "AUTH NTLM " + t1.encode64

	# receive Type2 Message, i hope
	line = readline s
	unless /334 (.+)/ =~ line
		raise RuntimeError, "i don't recognize this: #{line}"
	end
	t2 = Net::NTLM::Message.decode64($1)

	unless $user and $passwd
		target = t2.target_name
		target = Net::NTLM::decode_utf16le(target) if t2.has_flag?(:UNICODE)
		puts "Target: #{target}"
		print "User name: "
		($user = $stdin.readline).chomp!
		print "Password: "
		($passwd = $stdin.readline).chomp!
	end
	
	# send Type3 Message
	t3 = t2.response({:user => $user, :password => $passwd}, {:ntlmv2 => true})
	writeline s, t3.encode64

	# and result is...
	line = readline s

	unless /^235(.+)Authentication successful./i =~ line
		raise RuntimeError, "sorry, authentication failed."
	end
	
	# do real job here like...
	# from = $user
	# to = "billg"
	# writeline s, "MAIL FROM: #{from}"
	# readline s
	# writeline s, "RCPT TO: #{to}"
	# readline s
	# writeline s, "DATA"
	# readline s
	# writeline s, "From: #{from}"
	# writeline s, "To: #{to}"
	# writeline s, "blab blab blab..."
	# writeline s, "#{from}"
	# writeline s, "."
	# readline s

	# say bye
	writeline s, "QUIT"
	s.close
end

main

