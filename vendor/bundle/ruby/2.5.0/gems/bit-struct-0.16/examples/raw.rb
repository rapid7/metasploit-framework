require "socket"
require "./ip"

# A more substantial example of sending and receiving RAW packets.

begin
  rsock = Socket.open(Socket::PF_INET, Socket::SOCK_RAW, Socket::IPPROTO_RAW)
rescue Errno::EPERM
  $stderr.puts "Must run #{$0} as root."
  exit!
end

begin
  ssock = Socket.open(Socket::PF_INET, Socket::SOCK_RAW, Socket::IPPROTO_RAW)
  unless ssock.getsockopt(Socket::SOL_IP, Socket::IP_HDRINCL)
    puts "IP_HDRINCL is supposed to be the default for IPPROTO_RAW!"
    puts "setting IP_HDRINCL anyway"
    ssock.setsockopt(Socket::SOL_IP, Socket::IP_HDRINCL, true)
  end
rescue Errno::EPERM
  $stderr.puts "Must run #{$0} as root."
  exit!
end

Thread.new do
  loop do
    data, sender = rsock.recvfrom(8192)
    port, host = Socket.unpack_sockaddr_in(sender)
    out = "-"*80,
          "packet received from #{host}:#{port}:",
          IP.new(data).inspect_detailed,
          "-"*80
    puts out
    $stdout.flush
  end
end

addr = Socket.pack_sockaddr_in(1024, "localhost")
3.times do |i|
  ip = IP.new do |b|
    # ip_v and ip_hl are set for us by IP class
    b.ip_tos  = 0
    b.ip_id   = i+1
    b.ip_off  = 0
    b.ip_ttl  = 64
    b.ip_p    = Socket::IPPROTO_RAW
    b.ip_src  = "127.0.0.1"
    b.ip_dst  = "127.0.0.1"
    b.body    = "just another IP hacker"
    b.ip_len  = b.length
    b.ip_sum  = 0 # linux will calculate this for us (QNX won't?)
  end

  out = "-"*80,
        "packet sent:",
        ip.inspect_detailed,
        "-"*80
  puts out
  $stdout.flush
  ssock.send(ip, 0, addr)
  sleep 1
end
