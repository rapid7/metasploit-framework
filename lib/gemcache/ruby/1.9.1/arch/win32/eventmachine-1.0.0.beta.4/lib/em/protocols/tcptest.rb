#--
#
# Author:: Francis Cianfrocca (gmail: blackhedd)
# Homepage::  http://rubyeventmachine.com
# Date:: 16 July 2006
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
# 

module EventMachine
  module Protocols

    # @private
    class TcpConnectTester < Connection
      include EventMachine::Deferrable

      def self.test( host, port )
        EventMachine.connect( host, port, self )
      end

      def post_init
        @start_time = Time.now
      end

      def connection_completed
        @completed = true
        set_deferred_status :succeeded, (Time.now - @start_time)
        close_connection
      end

      def unbind
        set_deferred_status :failed, (Time.now - @start_time)  unless @completed
      end
    end

  end
end
