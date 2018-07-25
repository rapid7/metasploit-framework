# -*- coding: binary -*-
require 'rex'

module Net
module SSH

class CommandStream

  attr_accessor :channel, :thread, :error, :ssh
  attr_accessor :lsock, :rsock, :monitor

  module PeerInfo
    include ::Rex::IO::Stream
    attr_accessor :peerinfo
    attr_accessor :localinfo
  end

  def shell_requested(channel, success)
    raise "could not request ssh shell" unless success
    channel[:data] = ''

    channel.on_eof do
      cleanup
    end

    channel.on_close do
      cleanup
    end

    channel.on_data do |ch,data|
      self.rsock.write(data)
    end

    channel.on_extended_data do |ch, ctype, data|
      self.rsock.write(data)
    end

    self.channel = channel
  end

  def initialize(ssh, cmd = nil, cleanup = false)

    self.lsock, self.rsock = Rex::Socket.tcp_socket_pair()
    self.lsock.extend(Rex::IO::Stream)
    self.lsock.extend(PeerInfo)
    self.rsock.extend(Rex::IO::Stream)

    self.ssh = ssh
    self.thread = Thread.new(ssh,cmd,cleanup) do |rssh, rcmd, rcleanup|

      begin
        info = rssh.transport.socket.getpeername_as_array
        self.lsock.peerinfo  = "#{info[1]}:#{info[2]}"

        info = rssh.transport.socket.getsockname
        self.lsock.localinfo = "#{info[1]}:#{info[2]}"

        rssh.open_channel do |rch|
          if rcmd.nil?
            rch.send_channel_request("shell", &method(:shell_requested))
          else
            rch.exec(rcmd, &method(:shell_requested))
          end
        end

        self.monitor = Thread.new do
          while(true)
            next if not self.rsock.has_read_data?(1.0)
            buff = self.rsock.read(16384)
            break if not buff
            verify_channel
            self.channel.send_data(buff) if buff
          end
        end

        while true
          rssh.process(0.5) { true }
        end

      rescue ::Exception => e
        self.error = e
        #::Kernel.warn "BOO: #{e.inspect}"
        #::Kernel.warn e.backtrace.join("\n")
      ensure
        self.monitor.kill if self.monitor
      end

      # Shut down the SSH session if requested
      if !rcmd.nil? && rcleanup
        rssh.close
      end
    end
  end

  #
  # Prevent a race condition
  #
  def verify_channel
    while ! self.channel
      raise EOFError if ! self.thread.alive?
      ::IO.select(nil, nil, nil, 0.10)
    end
  end

  def cleanup
    self.monitor.kill
    self.lsock.close rescue nil
    self.rsock.close rescue nil
    self.ssh.close rescue nil
    self.thread.kill
  end

end
end
end

