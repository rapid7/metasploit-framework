#--
#
# Author:: Francis Cianfrocca (gmail: blackhedd)
# Homepage::  http://rubyeventmachine.com
# Date:: 25 Aug 2007
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

module EventMachine
  # Support for Erlang-style processes.
  #
  class SpawnedProcess
    # Send a message to the spawned process
    def notify *x
      me = self
      EM.next_tick {
        # A notification executes in the context of this
        # SpawnedProcess object. That makes self and notify
        # work as one would expect.
        #
        y = me.call(*x)
        if y and y.respond_to?(:pull_out_yield_block)
          a,b = y.pull_out_yield_block
          set_receiver a
          self.notify if b
        end
      }
    end
    alias_method :resume, :notify
    alias_method :run, :notify # for formulations like (EM.spawn {xxx}).run

    def set_receiver blk
      (class << self ; self ; end).class_eval do
        remove_method :call if method_defined? :call
        define_method :call, blk
      end
    end

  end

  # @private
  class YieldBlockFromSpawnedProcess
    def initialize block, notify
      @block = [block,notify]
    end
    def pull_out_yield_block
      @block
    end
  end

  # Spawn an erlang-style process
  def self.spawn &block
    s = SpawnedProcess.new
    s.set_receiver block
    s
  end

  # @private
  def self.yield &block
    return YieldBlockFromSpawnedProcess.new( block, false )
  end

  # @private
  def self.yield_and_notify &block
    return YieldBlockFromSpawnedProcess.new( block, true )
  end
end
