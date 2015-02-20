#!/usr/bin/ruby
#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# this is a TCP proxy which dumps the transmitted data in hex on stdout
# usage: tcp_proxy <lhost> <lport> <rhost> <rport> [<timeout_s>]

require 'socket'
require File.join(File.dirname(__FILE__), 'hexdump')

def bouncepkt(clt, srv, timeout=nil)
  s2c = ''
  c2s = ''
  loop do
    break if not IO.select([clt, srv], nil, nil, timeout)

    while srv and s2c.length < 1024*16 and IO.select([srv], nil, nil, 0)
      str = (srv.read(1) rescue nil)
      if not str or str.empty?
        srv = false
      else
        s2c << str
      end
    end

    while clt and c2s.length < 1024*16 and IO.select([clt], nil, nil, 0)
      str = (clt.read(1) rescue nil)
      if not str or str.empty?
        clt = false
      else
        c2s << str
      end
    end

    if clt and s2c.length > 0 and IO.select(nil, [clt], nil, 0)
      puts Time.now.strftime('s -> c  %H:%M:%S')
      s2c.hexdump(:fmt => ['c', 'a'])
      clt.write s2c
      s2c.replace ''
    end

    if srv and c2s.length > 0 and IO.select(nil, [srv], nil, 0)
      puts Time.now.strftime('c -> s  %H:%M:%S')
      c2s.hexdump(:fmt => ['c', 'a'])
      srv.write c2s
      c2s.replace ''
    end
    break if not clt or not srv
  end
end


if $0 == __FILE__
if ARGV.length < 4
  abort "usage: bnc <lhost> <lport> <rhost> <rport> [<timeout_s>]"
end

lhost = ARGV.shift
lport = Integer(ARGV.shift)
rhost = ARGV.shift
rport = Integer(ARGV.shift)
timeout = Float(ARGV.shift) if not ARGV.empty?

s = TCPServer.new(lhost, lport)

loop do
  puts "waiting..."
  a = s.accept
  puts "incoming connection"
  c = TCPSocket.new(rhost, rport)
  
  begin
    bouncepkt(a, c, timeout)
  rescue SystemCallError
  end

  puts "connection closed"
  a.close
  c.close
end
end
