#!ruby

require 'socket'

$port = 67 

def test(dstip = '255.255.255.255')
	s = UDPSocket.open
	s.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, 1)
	s.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
	s.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, true)
	s.bind('<any>', 68)
	s.send("test", 0, dstip, 67)

end


sThread = Thread.start do     # run server in a thread
	server = UDPSocket.open
	server.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
	server.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, true)
	server.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, 1)
	server.bind('<any>', $port)
	while (1)
		request = server.recvfrom(1024)
		p request
	end
end

test()
test()

sThread.join
