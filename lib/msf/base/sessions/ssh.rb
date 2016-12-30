# -*- coding: binary -*-
require 'msf/base'

class Msf::Sessions::SSH
  require 'msf/base/sessions/ssh/ui/console'

  include Msf::Session
  include Msf::Session::Comm
  include Msf::Session::Interactive

  # @return [Net::SSH::Connection::Session]
  attr_accessor :ssh
  attr_accessor :console
  attr_accessor :framework
  attr_accessor :platform
  attr_accessor :user_input
  attr_accessor :user_output

  # @return [Bool]
  attr_accessor :interacting

  def self.type
    "ssh"
  end

  def type
    self.class.type
  end

  def session_host
    sock = self.ssh.transport.socket
    sock.peerhost
  end

  def tunnel_peer
    sock = self.ssh.transport.socket

    "#{sock.peerhost}:#{sock.peerport}"
  end

  # @param ssh [Net::SSH::Connection::Session]
  def initialize(ssh, opts={})
    @ssh = ssh
    @platform = 'ssh'
    self.console = Ui::Console.new(self)
  end

  def alive?
    true
  end

  # @param param [Rex::Socket::Parameters]
  def create(param)
    if param.tcp? && !param.server?

      @ssh.forward.local(
        param.localhost,
        param.localport,
        param.peerhost,
        param.peerport
      )

    end
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
    console.interact { self.interacting != true }
    raise EOFError if (console.stopped? == true)
  end
end
