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



require 'singleton'

module Evma

class ContainerHasObject < Exception; end
class UnsupportedCallback < Exception; end
class UnknownTarget < Exception; end

class Container
  include Singleton

  def initialize
    @objects = {}
  end

  def self.store obj
    instance.store obj
  end

  def self.callback target, opcode, data
    instance.callback target, opcode, data
  end

  def store obj
    sig = obj.signature
    raise ContainerHasObject.new(sig) if @objects.has_key?(sig)
    @objects[sig] = obj
  end

  def callback target, opcode, data
    case opcode
    when 101 # received data
      obj = @objects[target] or raise UnknownTarget.new( target )
      obj.receive_data data
    when 102 # unbind
      obj = @objects[target] or raise UnknownTarget.new( target )
      obj.unbind
      @objects.delete obj.signature
    when 103 # accept
      obj = @objects[target] or raise UnknownTarget.new( target )
      obj.accept data
    else
      raise UnsupportedCallback.new( opcode.to_s )
    end
  end

end # class Container
end # module Evma

