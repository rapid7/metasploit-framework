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
class Protocol

  attr_reader :signature

  def initialize sig
    @signature = sig
  end

  def unbind
  end

  def close
    Evma::Reactor.instance # ensure initialized
    EventMachine.close_connection signature, false
  end

  def close_after_writing
    Evma::Reactor.instance # ensure initialized
    EventMachine.close_connection signature, true
  end

end # class Protocol
end # module Evma


###########################################

module Evma
class StreamProtocol < Protocol

  def initialize sig
    super
  end

  def send_data data
    Evma::Reactor.instance # ensure initialized
    EventMachine.send_data signature, data, data.length
  end

end # class Protocol
end # module Evma


###########################################

module Evma
class DatagramProtocol < Protocol

  def initialize sig
    super
  end

  def send_message data
    Evma::Reactor.instance # ensure initialized
    raise "unimplemented"
  end

end # class Protocol
end # module Evma


