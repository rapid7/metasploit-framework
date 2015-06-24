# -*- coding: binary -*-
require 'rex/socket'

module Msf
module Handler

###
#
# This module implements the reverse Rex::Socket::Comm handlng.
#
###
module ReverseTcpComm

  def initialize(info = {})
    super

    register_advanced_options(
      [
        OptString.new('ReverseListenerComm', [ false, 'The specific communication channel to use for this listener']),
      ], Msf::Handler::ReverseTcpComm)
  end

  def select_comm
    rl_comm = datastore['ReverseListenerComm'].to_s
    case rl_comm
    when 'local'
      comm = ::Rex::Socket::Comm::Local
    when /\A[0-9]+\Z/
      comm = framework.sessions[rl_comm.to_i]
      raise(RuntimeError, "Reverse Listener Comm (Session #{rl_comm}) does not exist") unless comm
      raise(RuntimeError, "Reverse Listener Comm (Session #{rl_comm}) does not implement Rex::Socket::Comm") unless comm.is_a? ::Rex::Socket::Comm
    when nil, ''
      comm = nil
    else
      raise(RuntimeError, "Reverse Listener Comm '#{rl_comm}' is invalid")
    end

    comm
  end
end

end
end
