#--
#
# Author:: Francis Cianfrocca (gmail: blackhedd)
# Homepage::  http://rubyeventmachine.com
# Date:: 16 Jul 2006
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

#--
# This defines EventMachine::Deferrable#future, which requires
# that the rest of EventMachine::Deferrable has already been seen.
# (It's in deferrable.rb.)

module EventMachine
    module Deferrable

      # A future is a sugaring of a typical deferrable usage.
      #--
      # Evaluate arg (which may be an expression or a block).
      # What's the class of arg?
      # If arg is an ordinary expression, then return it.
      # If arg is deferrable (responds to :set_deferred_status),
      # then look at the arguments. If either callback or errback
      # are defined, then use them. If neither are defined, then
      # use the supplied block (if any) as the callback.
      # Then return arg.
      def self.future arg, cb=nil, eb=nil, &blk
        arg = arg.call if arg.respond_to?(:call)

        if arg.respond_to?(:set_deferred_status)
          if cb || eb
            arg.callback(&cb) if cb
            arg.errback(&eb) if eb
          else
            arg.callback(&blk) if blk
          end
        end

        arg
      end

    end
end

