# frozen_string_literal: true

# -*- coding: binary -*-
require 'msf/base'

# An SSH session
class Msf::Sessions::SSH
  require 'msf/base/sessions/ssh/ui/console'

  include Msf::Session
  include Msf::Session::Comm
  include Msf::Session::Interactive

  attr_accessor :console

  attr_accessor :framework

  # @return [Bool]
  attr_accessor :interacting

  # @reteurn [String]
  attr_accessor :platform

  # @return [Net::SSH::Connection::Session]
  attr_accessor :ssh

  attr_accessor :user_input

  attr_accessor :user_output

  # @reteurn [String] "ssh"
  def self.type
    "ssh"
  end

  # @see .type
  def type
    self.class.type
  end

  # @reteurn [String]
  def arch
    'ssh'
  end

  # @see Rex::Socket#peerhost
  def session_host
    sock = ssh.transport.socket
    sock.peerhost
  end

  def tunnel_peer
    sock = ssh.transport.socket

    "#{sock.peerhost}:#{sock.peerport}"
  end

  # @param ssh [Net::SSH::Connection::Session]
  def initialize(ssh, opts = {})
    @ssh = ssh
    @platform = 'cmd'
    @framework = opts[:framework]
    self.console = Ui::Console.new(self)
  end

  def alive?
    # XXX
    true
  end

  # @param param [Rex::Socket::Parameters]
  def create(param)
    $stderr.puts("Creating socket")
    if param.tcp? && !param.server?

      @ssh.forward.local(
        param.localhost,
        param.localport,
        param.peerhost,
        param.peerport
      )
    end
  end

  # @return [Numeric] local listening port
  def forward_local(lhost, lport, rhost, rport)
    listening_port = @ssh.forward.local(lhost, lport, rhost, rport)
    spawn_forwarding_processor

    listening_port
  end

  def spawn_forwarding_processor
    $stderr.puts("@forwarding_processor: #{@forwarding_processor.inspect}")
    return if @forwarding_processor&.alive?
    return unless @forwarding_processor.nil?

    @forwarding_processor = framework.threads.spawn("Session #{sid} ssh_fwd", false) do
      $stderr.puts("starting forwarding thread")
      until ssh.forward.active_locals.empty?
        # If all ssh channels have hit eof, this will return immediately
        @ssh.loop
        sleep 0.5
      end
      $stderr.puts("forwarding thread done")
    end
  end

  def cleanup
    super

    return if @forwarding_processor.nil?

    @forwarding_processor.kill
    @forwarding_processor = nil
  end

  ##
  #
  # Msf::Session::Interactive implementors
  #
  ##

  def init_ui(input, output)
    self.user_input = input
    self.user_output = output
    console.init_ui(input, output)
    console.set_log_source(log_source)

    super
  end

  def reset_ui
    console.unset_log_source
    console.reset_ui
  end

  def _interact
    console.interact { interacting != true }
    raise EOFError if console.stopped? == true
  end
end
