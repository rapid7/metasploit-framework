require "socket"
require "./ip"

# Example of using the IP class to receive ping (ICMP) messages.

begin
  rsock = Socket.open(Socket::PF_INET, Socket::SOCK_RAW, Socket::IPPROTO_ICMP)
rescue Errno::EPERM
  $stderr.puts "Must run #{$0} as root."
  exit!
end

Thread.new do
  loop do
    data, sender = rsock.recvfrom(8192)
    port, host = Socket.unpack_sockaddr_in(sender)
    puts "-"*80,
         "packet received from #{host}:#{port}:",
         IP.new(data).inspect_detailed,
         "-"*80
    $stdout.flush
  end
end

system "ping 127.0.0.1"
