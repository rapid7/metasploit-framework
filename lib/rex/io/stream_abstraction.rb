#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'socket'
require 'fcntl'

module Rex
module IO

###
#
# This class provides an abstraction to a stream based
# connection through the use of a streaming socketpair.
#
###
module StreamAbstraction

  ###
  #
  # Extension information for required Stream interface.
  #
  ###
  module Ext

    #
    # Initializes peer information.
    #
    def initinfo(peer,local)
      @peer = peer
      @local = local
    end

    #
    # Symbolic peer information.
    #
    def peerinfo
      (@peer || "Remote Pipe")
    end

    #
    # Symbolic local information.
    #
    def localinfo
      (@local || "Local Pipe")
    end
  end

  #
  # This method creates a streaming socket pair and initializes it.
  #
  def initialize_abstraction
    self.lsock, self.rsock = Rex::Socket.tcp_socket_pair()
    self.lsock.extend(Rex::IO::Stream)
    self.lsock.extend(Ext)
    self.rsock.extend(Rex::IO::Stream)

    self.monitor_rsock
  end

  #
  # This method cleans up the abstraction layer.
  #
  def cleanup_abstraction
    self.lsock.close if (self.lsock)
    self.rsock.close if (self.rsock)

    self.lsock = nil
    self.rsock = nil
  end

  #
  # Low-level write to the local side.
  #
  def syswrite(buffer)
    lsock.syswrite(buffer)
  end

  #
  # Low-level read from the local side.
  #
  def sysread(length)
    lsock.sysread(length)
  end

  #
  # Shuts down the local side of the stream abstraction.
  #
  def shutdown(how)
    lsock.shutdown(how)
  end

  #
  # Closes both sides of the stream abstraction.
  #
  def close
    cleanup_abstraction
  end

  #
  # Symbolic peer information.
  #
  def peerinfo
    "Remote-side of Pipe"
  end

  #
  # Symbolic local information.
  #
  def localinfo
    "Local-side of Pipe"
  end

  #
  # The left side of the stream.
  #
  attr_reader :lsock
  #
  # The right side of the stream.
  #
  attr_reader :rsock

protected

  def monitor_rsock
    self.monitor_thread = Rex::ThreadFactory.spawn("StreamMonitorRemote", false) {
      loop do
        closed = false
        buf    = nil

        if not self.rsock
          wlog("monitor_rsock: the remote socket is nil, exiting loop")
          break
        end

        begin
          s = Rex::ThreadSafe.select( [ self.rsock ], nil, nil, 0.2 )
          if( s == nil || s[0] == nil )
            next
          end
        rescue Exception => e
          wlog("monitor_rsock: exception during select: #{e.class} #{e}")
          closed = true
        end

        if( closed == false )
          begin
            buf = self.rsock.sysread( 32768 )
            if buf == nil
              closed = true
              wlog("monitor_rsock: closed remote socket due to nil read")
            end
          rescue EOFError => e
            closed = true
            dlog("monitor_rsock: EOF in rsock")
          rescue ::Exception => e
            closed = true
            wlog("monitor_rsock: exception during read: #{e.class} #{e}")
          end
        end

        if( closed == false )
          total_sent   = 0
          total_length = buf.length
          while( total_sent < total_length )
            begin
              data = buf[total_sent, buf.length]

              # Note that this must be write() NOT syswrite() or put() or anything like it.
              # Using syswrite() breaks SSL streams.
              sent = self.write( data )

              # sf: Only remove the data off the queue is write was successfull.
              #     This way we naturally perform a resend if a failure occured.
              #     Catches an edge case with meterpreter TCP channels where remote send
              #     failes gracefully and a resend is required.
              if (sent.nil?)
                closed = true
                wlog("monitor_rsock: failed writing, socket must be dead")
                break
              elsif (sent > 0)
                total_sent += sent
              end
            rescue ::IOError, ::EOFError => e
              closed = true
              wlog("monitor_rsock: exception during write: #{e.class} #{e}")
              break
            end
          end
        end

        if( closed )
          begin
            self.close_write if self.respond_to?('close_write')
          rescue IOError
          end
          break
        end
      end
    }
  end

protected
  attr_accessor :monitor_thread
  attr_writer :lsock
  attr_writer :rsock

end

end; end

