#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'ipaddr'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Net

###
#
# This class represents a connection (listening, connected)
# on the remote machine.
#
###
class Netstat

  ##
  #
  # Constructor
  #
  ##

  #
  # Returns a netstat entry and initializes it to the supplied
  # parameters.
  #
  def initialize(opts={})
    self.local_addr   = IPAddr.new_ntoh(opts[:local_addr]).to_s
    self.remote_addr  = IPAddr.new_ntoh(opts[:remote_addr]).to_s
    self.local_port   = opts[:local_port]
    self.remote_port  = opts[:remote_port]
    self.protocol     = opts[:protocol]
    self.state        = opts[:state]
    self.uid          = opts[:uid] || 0
    self.inode        = opts[:inode] || 0
    self.pid_name     = opts[:pid_name]

    self.local_addr_str  = sprintf("%s:%d",self.local_addr, self.local_port)
    if self.remote_port == 0
      port = "*"
    else
      port = self.remote_port.to_s
    end
    self.remote_addr_str = sprintf("%s:%s",self.remote_addr, port)
  end


  #
  # The local address of the connection
  #
  attr_accessor :local_addr
  #
  # The remote address (peer) of the connection
  #
  attr_accessor :remote_addr
  #
  # The local port of the connection.
  #
  attr_accessor :local_port
  #
  # The remote port of the connection.
  #
  attr_accessor :remote_port
  #
  # The protocol type (tcp/tcp6/udp/udp6)
  #
  attr_accessor :protocol
  #
  # The state  of the connection (close, listening, syn_sent...)
  #
  attr_accessor :state
  #
  # The uid of the user who started the process to which the connection belongs to
  #
  attr_accessor :uid
  #
  # The socket inode
  #
  attr_accessor :inode
  #
  # The name of the process to which the connection belongs to
  #
  attr_accessor :pid_name
  #
  # The local address of the connection plus the port
  #
  attr_accessor :local_addr_str
  #
  # The remote address (peer) of the connection plus the port or *
  #
  attr_accessor :remote_addr_str
end

end; end; end; end; end; end
