#--
#
# Author:: Francis Cianfrocca (gmail: blackhedd)
# Homepage::  http://rubyeventmachine.com
# Date:: 15 November 2006
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
    # A protocol that handles line-oriented data with interspersed binary text.
    #
    # This version is optimized for performance. See EventMachine::Protocols::LineText2
    # for a version which is optimized for correctness with regard to binary text blocks
    # that can switch back to line mode.
    class LineAndTextProtocol < Connection
      MaxBinaryLength = 32*1024*1024

      def initialize *args
        super
        lbp_init_line_state
      end

      def receive_data data
        if @lbp_mode == :lines
          begin
            @lpb_buffer.extract(data).each do |line|
              receive_line(line.chomp) if respond_to?(:receive_line)
            end
          rescue
            receive_error('overlength line') if respond_to?(:receive_error)
            close_connection
            return
          end
        else
          if @lbp_binary_limit > 0
            wanted = @lbp_binary_limit - @lbp_binary_bytes_received
            chunk = nil
            if data.length > wanted
              chunk = data.slice!(0...wanted)
            else
              chunk = data
              data = ""
            end
            @lbp_binary_buffer[@lbp_binary_bytes_received...(@lbp_binary_bytes_received+chunk.length)] = chunk
            @lbp_binary_bytes_received += chunk.length
            if @lbp_binary_bytes_received == @lbp_binary_limit
              receive_binary_data(@lbp_binary_buffer) if respond_to?(:receive_binary_data)
              lbp_init_line_state
            end
            receive_data(data) if data.length > 0
          else
            receive_binary_data(data) if respond_to?(:receive_binary_data)
            data = ""
          end
        end
      end

      def unbind
        if @lbp_mode == :binary and @lbp_binary_limit > 0
          if respond_to?(:receive_binary_data)
            receive_binary_data( @lbp_binary_buffer[0...@lbp_binary_bytes_received] )
          end
        end
      end

      # Set up to read the supplied number of binary bytes.
      # This recycles all the data currently waiting in the line buffer, if any.
      # If the limit is nil, then ALL subsequent data will be treated as binary
      # data and passed to the upstream protocol handler as we receive it.
      # If a limit is given, we'll hold the incoming binary data and not
      # pass it upstream until we've seen it all, or until there is an unbind
      # (in which case we'll pass up a partial).
      # Specifying nil for the limit (the default) means there is no limit.
      # Specifiyng zero for the limit will cause an immediate transition back to line mode.
      #
      def set_binary_mode size = nil
        if @lbp_mode == :lines
          if size == 0
            receive_binary_data("") if respond_to?(:receive_binary_data)
            # Do no more work here. Stay in line mode and keep consuming data.
          else
            @lbp_binary_limit = size.to_i # (nil will be stored as zero)
            if @lbp_binary_limit > 0
              raise "Overlength" if @lbp_binary_limit > MaxBinaryLength # arbitrary sanity check
              @lbp_binary_buffer = "\0" * @lbp_binary_limit
              @lbp_binary_bytes_received = 0
            end

            @lbp_mode = :binary
            receive_data @lpb_buffer.flush
          end
        else
          raise "invalid operation"
        end
      end

      #--
      # For internal use, establish protocol baseline for handling lines.
      def lbp_init_line_state
        @lpb_buffer = BufferedTokenizer.new("\n")
        @lbp_mode = :lines
      end
      private :lbp_init_line_state
    end
  end
end
