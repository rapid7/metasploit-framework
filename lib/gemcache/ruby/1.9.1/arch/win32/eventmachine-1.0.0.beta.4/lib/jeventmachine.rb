#--
#
# Author:: Francis Cianfrocca (gmail: blackhedd)
# Homepage::  http://rubyeventmachine.com
# Date:: 8 Apr 2006
# 
# See EventMachine and EventMachine::Connection for documentation and
# usage examples.
#
#----------------------------------------------------------------------------
#
# Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
# Gmail: blackhedd
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of either: 1) the GNU General Public License
# as published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version; or 2) Ruby's License.
# 
# See the file COPYING for complete licensing information.
#
#---------------------------------------------------------------------------
#
# 

# This module provides "glue" for the Java version of the EventMachine reactor core.
# For C++ EventMachines, the analogous functionality is found in ext/rubymain.cpp,
# which is a garden-variety Ruby-extension glue module.

require 'java'
require 'rubyeventmachine'
require 'socket'

java_import java.io.FileDescriptor
java_import java.nio.channels.SocketChannel
java_import java.lang.reflect.Field

module JavaFields
  def set_field(key, value)
    field = getClass.getDeclaredField(key)
    field.setAccessible(true)
    if field.getType.toString == 'int'
      field.setInt(self, value)
    else
      field.set(self, value)
    end
  end

  def get_field(key)
    field = getClass.getDeclaredField(key)
    field.setAccessible(true)
    field.get(self)
  end
end

FileDescriptor.send :include, JavaFields
SocketChannel.send :include, JavaFields

module EventMachine
  # TODO: These event numbers are defined in way too many places.
  # DRY them up.
  # @private
  TimerFired = 100
  # @private
  ConnectionData = 101
  # @private
  ConnectionUnbound = 102
  # @private
  ConnectionAccepted = 103
  # @private
  ConnectionCompleted = 104
  # @private
  LoopbreakSignalled = 105
  # @private
  ConnectionNotifyReadable = 106
  # @private
  ConnectionNotifyWritable = 107
  # @private
  SslHandshakeCompleted = 108

  # Exceptions that are defined in rubymain.cpp
  class ConnectionError < RuntimeError; end
  class ConnectionNotBound < RuntimeError; end
  class UnknownTimerFired < RuntimeError; end
  class Unsupported < RuntimeError; end

  # This thunk class used to be called EM, but that caused conflicts with
  # the alias "EM" for module EventMachine. (FC, 20Jun08)
  class JEM < com.rubyeventmachine.EmReactor
    def eventCallback a1, a2, a3, a4
      s = String.from_java_bytes(a3.array[a3.position...a3.limit]) if a3
      EventMachine::event_callback a1, a2, s || a4
      nil
    end
  end
  # class Connection < com.rubyeventmachine.Connection
  #   def associate_callback_target sig
  #     # No-op for the time being.
  #   end
  # end
  def self.initialize_event_machine
    @em = JEM.new
  end
  def self.release_machine
    @em = nil
  end
  def self.add_oneshot_timer interval
    @em.installOneshotTimer interval
  end
  def self.run_machine
    @em.run
  end
  def self.stop
    @em.stop
  end
  def self.start_tcp_server server, port
    @em.startTcpServer server, port
  end
  def self.stop_tcp_server sig
    @em.stopTcpServer sig
  end
  def self.start_unix_server filename
    # TEMPORARILY unsupported until someone figures out how to do it.
    raise "unsupported on this platform"
  end
  def self.send_data sig, data, length
    @em.sendData sig, data.to_java_bytes
  end
  def self.send_datagram sig, data, length, address, port
    @em.sendDatagram sig, data.to_java_bytes, length, address, port
  end
  def self.connect_server server, port
    bind_connect_server nil, nil, server, port
  end
  def self.bind_connect_server bind_addr, bind_port, server, port
    @em.connectTcpServer bind_addr, bind_port.to_i, server, port
  end
  def self.close_connection sig, after_writing
    @em.closeConnection sig, after_writing
  end
  def self.set_comm_inactivity_timeout sig, interval
    @em.setCommInactivityTimeout sig, interval
  end
  def self.set_pending_connect_timeout sig, val
  end
  def self.set_heartbeat_interval val
  end
  def self.start_tls sig
    @em.startTls sig
  end
  def self.ssl?
    false
  end
  def self.signal_loopbreak
    @em.signalLoopbreak
  end
  def self.set_timer_quantum q
    @em.setTimerQuantum q
  end
  def self.epoll
    # Epoll is a no-op for Java.
    # The latest Java versions run epoll when possible in NIO.
  end
  def self.epoll= val
  end
  def self.kqueue
  end
  def self.kqueue= val
  end
  def self.epoll?
    false
  end
  def self.kqueue?
    false
  end
  def self.set_rlimit_nofile n_descriptors
    # Currently a no-op for Java.
  end
  def self.open_udp_socket server, port
    @em.openUdpSocket server, port
  end
  def self.invoke_popen cmd
    # TEMPORARILY unsupported until someone figures out how to do it.
    raise "unsupported on this platform"
  end
  def self.read_keyboard
    # TEMPORARILY unsupported until someone figures out how to do it.
    raise "temporarily unsupported on this platform"
  end
  def self.set_max_timer_count num
    # harmless no-op in Java. There's no built-in timer limit.
    @max_timer_count = num
  end
  def self.get_max_timer_count
    # harmless no-op in Java. There's no built-in timer limit.
    @max_timer_count || 100_000
  end
  def self.library_type
    :java
  end
  def self.get_peername sig
    if peer = @em.getPeerName(sig)
      Socket.pack_sockaddr_in(*peer)
    end
  end
  # @private
  def self.attach_fd fileno, watch_mode
    # 3Aug09: We could pass in the actual SocketChannel, but then it would be modified (set as non-blocking), and
    # we would need some logic to make sure detach_fd below didn't clobber it. For now, we just always make a new
    # SocketChannel for the underlying file descriptor
    # if fileno.java_kind_of? SocketChannel
    #   ch = fileno
    #   ch.configureBlocking(false)
    #   fileno = nil
    # elsif fileno.java_kind_of? java.nio.channels.Channel

    if fileno.java_kind_of? java.nio.channels.Channel
      field = fileno.getClass.getDeclaredField('fdVal')
      field.setAccessible(true)
      fileno = field.get(fileno)
    else
      raise ArgumentError, 'attach_fd requires Java Channel or POSIX fileno' unless fileno.is_a? Fixnum
    end

    if fileno == 0
      raise "can't open STDIN as selectable in Java =("
    elsif fileno.is_a? Fixnum
      # 8Aug09: The following code is specific to the sun jvm's SocketChannelImpl. Is there a cross-platform
      # way of implementing this? If so, also remember to update EventableSocketChannel#close and #cleanup
      fd = FileDescriptor.new
      fd.set_field 'fd', fileno

      ch = SocketChannel.open
      ch.configureBlocking(false)
      ch.kill
      ch.set_field 'fd', fd
      ch.set_field 'fdVal', fileno
      ch.set_field 'state', ch.get_field('ST_CONNECTED')
    end

    @em.attachChannel(ch,watch_mode)
  end
  def self.detach_fd sig
    if ch = @em.detachChannel(sig)
      ch.get_field 'fdVal'
    end
  end

  def self.set_notify_readable sig, mode
    @em.setNotifyReadable(sig, mode)
  end
  def self.set_notify_writable sig, mode
    @em.setNotifyWritable(sig, mode)
  end

  def self.is_notify_readable sig
    @em.isNotifyReadable(sig)
  end
  def self.is_notify_writable sig
    @em.isNotifyWritable(sig)
  end
  def self.get_connection_count
    @em.getConnectionCount
  end

  def self.set_tls_parms(sig, params)
  end
  def self.start_tls(sig)
  end
  def self.send_file_data(sig, filename)
  end

  class Connection
    def associate_callback_target sig
      # No-op for the time being
    end
  end
end

