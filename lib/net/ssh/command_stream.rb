# -*- coding: binary -*-

class Net::SSH::CommandStream

  attr_accessor :channel, :thread, :error, :ssh, :session, :logger
  attr_accessor :lsock, :rsock, :monitor

  module PeerInfo
    include ::Rex::IO::Stream
    attr_accessor :peerinfo
    attr_accessor :localinfo
  end

  def shell_requested(channel, success)
    unless success
      error = Net::SSH::ChannelRequestFailed.new('Shell/exec channel request failed')
      handle_error(error: error)
    end

    self.channel = channel

    channel[:data] = ''
    channel[:extended_data] = ''

    channel.on_eof do
      cleanup
    end

    channel.on_close do
      cleanup
    end

    channel.on_data do |ch, data|
      self.rsock.write(data)
      channel[:data] << data
    end

    channel.on_extended_data do |ch, ctype, data|
      self.rsock.write(data)
      channel[:extended_data] << data
    end
  end

  def initialize(ssh, cmd = nil, pty: false, cleanup: false, session: nil, logger: nil)
    self.session = session
    self.logger = logger
    self.lsock, self.rsock = Rex::Socket.tcp_socket_pair()
    self.lsock.extend(Rex::IO::Stream)
    self.lsock.extend(PeerInfo)
    self.rsock.extend(Rex::IO::Stream)

    self.ssh = ssh
    self.thread = Thread.new(ssh, cmd, pty, cleanup) do |rssh, rcmd, rpty, rcleanup|
      info = rssh.transport.socket.getpeername_as_array
      if Rex::Socket.is_ipv6?(info[1])
        self.lsock.peerinfo = "[#{info[1]}]:#{info[2]}"
      else
        self.lsock.peerinfo = "#{info[1]}:#{info[2]}"
      end

      info = rssh.transport.socket.getsockname
      if Rex::Socket.is_ipv6?(info[1])
        self.lsock.localinfo = "[#{info[1]}]:#{info[2]}"
      else
        self.lsock.localinfo = "#{info[1]}:#{info[2]}"
      end

      channel = rssh.open_channel do |rch|
        # A PTY will write us to {u,w}tmp and lastlog
        rch.request_pty if rpty

        if rcmd.nil?
          rch.send_channel_request('shell', &method(:shell_requested))
        else
          rch.exec(rcmd, &method(:shell_requested))
        end
      end

      channel.on_open_failed do |ch, code, desc|
        error = Net::SSH::ChannelOpenFailed.new(code, 'Session channel open failed')
        handle_error(error: error)
      end

      self.monitor = Thread.new do
        begin
          Kernel.loop do
            next if not self.rsock.has_read_data?(1.0)

            buff = self.rsock.read(16384)
            break if not buff

            verify_channel
            self.channel.send_data(buff) if buff
          end
        rescue ::StandardError => e
          handle_error(error: e)
        end
      end

      begin
        Kernel.loop { rssh.process(0.5) { true } }
      rescue ::StandardError => e
        handle_error(error: e)
      end

      # Shut down the SSH session if requested
      if !rcmd.nil? && rcleanup
        rssh.close
      end
    end
  rescue ::StandardError => e
    # XXX: This won't be set UNTIL there's a failure from a thread
    handle_error(error: e)
  ensure
    self.monitor.kill if self.monitor
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

  def handle_error(error: nil)
    self.error = error if error

    if self.logger
      self.logger.print_error("SSH Command Stream encountered an error: #{self.error} (Server Version: #{self.ssh.transport.server_version.version})")
    end

    cleanup
  end

  def cleanup
    self.session.alive = false if self.session
    self.monitor.kill
    self.lsock.close rescue nil
    self.rsock.close rescue nil
    self.ssh.close rescue nil
    self.thread.kill
  end

end
