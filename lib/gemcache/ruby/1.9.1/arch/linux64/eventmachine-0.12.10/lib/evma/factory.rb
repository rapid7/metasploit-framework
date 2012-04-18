# $Id$
#
# Author:: Francis Cianfrocca (gmail: blackhedd)
# Homepage::  http://rubyeventmachine.com
# Date:: 19 May 2006
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


module Evma
class ProtocolFactory < Protocol

  #--
  # default implementation raises an exception.
  # we expect subclasses to override this.
  # we can't do anything reasonable here because
  def accept new_object
    # don't bother calling Evma::Reactor.instance, since only Reactor can call accept
    Evma::Container.store Evma::Protocol.new( new_object )
    EventMachine.close_connection new_object, false
  end


end # class ProtocolFactory
end # module Evma

######################################

module Evma
class TcpSocket

  def self.connect server, port, protocol_handler = Evma::Protocol
    Evma::Reactor.instance # ensure initialization
    sig = EventMachine.connect_server server, port
    Evma::Container.store protocol_handler.new( sig )
  end

end
end # module Evma

######################################

module Evma
class TcpServerFactory < Evma::ProtocolFactory

  def initialize server, port, protocol_handler = Evma::Protocol
    Evma::Reactor.instance # ensure initialization
    sig = EventMachine.start_tcp_server server, port
    super sig
    @protocol_handler = protocol_handler
    Evma::Container.store self
  end

  def accept new_obj
    # don't bother calling Evma::Reactor.instance, since only Reactor can call accept
    Evma::Container.store @protocol_handler.new( new_obj )
  end

end
end # module Evma

