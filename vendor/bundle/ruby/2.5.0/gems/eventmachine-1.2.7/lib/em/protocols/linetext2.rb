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

module EventMachine
  module Protocols
    # In the grand, time-honored tradition of re-inventing the wheel, we offer
    # here YET ANOTHER protocol that handles line-oriented data with interspersed
    # binary text. This one trades away some of the performance optimizations of
    # EventMachine::Protocols::LineAndTextProtocol in order to get better correctness
    # with regard to binary text blocks that can switch back to line mode. It also
    # permits the line-delimiter to change in midstream.
    # This was originally written to support Stomp.
    module LineText2
      # TODO! We're not enforcing the limits on header lengths and text-lengths.
      # When we get around to that, call #receive_error if the user defined it, otherwise
      # throw exceptions.

      MaxBinaryLength = 32*1024*1024

      #--
      # Will loop internally until there's no data left to read.
      # That way the user-defined handlers we call can modify the
      # handling characteristics on a per-token basis.
      #
      def receive_data data
        return unless (data and data.length > 0)

        # Do this stuff in lieu of a constructor.
        @lt2_mode ||= :lines
        @lt2_delimiter ||= "\n"
        @lt2_linebuffer ||= []

        remaining_data = data

        while remaining_data.length > 0
          if @lt2_mode == :lines
            delimiter_string = case @lt2_delimiter
            when Regexp
              remaining_data.slice(@lt2_delimiter)
            else
              @lt2_delimiter
            end
            ix = remaining_data.index(delimiter_string) if delimiter_string
            if ix
              @lt2_linebuffer << remaining_data[0...ix]
              ln = @lt2_linebuffer.join
              @lt2_linebuffer.clear
              if @lt2_delimiter == "\n"
                ln.chomp!
              end
              receive_line ln
              remaining_data = remaining_data[(ix+delimiter_string.length)..-1]
            else
              @lt2_linebuffer << remaining_data
              remaining_data = ""
            end
          elsif @lt2_mode == :text
            if @lt2_textsize
              needed = @lt2_textsize - @lt2_textpos
              will_take = if remaining_data.length > needed
                            needed
                          else
                            remaining_data.length
                          end

              @lt2_textbuffer << remaining_data[0...will_take]
              tail = remaining_data[will_take..-1]

              @lt2_textpos += will_take
              if @lt2_textpos >= @lt2_textsize
                # Reset line mode (the default behavior) BEFORE calling the
                # receive_binary_data. This makes it possible for user code
                # to call set_text_mode, enabling chains of text blocks
                # (which can possibly be of different sizes).
                set_line_mode
                receive_binary_data @lt2_textbuffer.join
                receive_end_of_binary_data
              end

              remaining_data = tail
            else
              receive_binary_data remaining_data
              remaining_data = ""
            end
          end
        end
      end

      # The line delimiter may be a regular expression or a string.  Anything
      # passed to set_delimiter other than a regular expression will be
      # converted to a string.
      def set_delimiter delim
        @lt2_delimiter = case delim
        when Regexp
          delim
        else
          delim.to_s
        end
      end

      # Called internally but also exposed to user code, for the case in which
      # processing of binary data creates a need to transition back to line mode.
      # We support an optional parameter to "throw back" some data, which might
      # be an umprocessed chunk of the transmitted binary data, or something else
      # entirely.
      def set_line_mode data=""
        @lt2_mode = :lines
        (@lt2_linebuffer ||= []).clear
        receive_data data.to_s
      end

      def set_text_mode size=nil
        if size == 0
          set_line_mode
        else
          @lt2_mode = :text
          (@lt2_textbuffer ||= []).clear
          @lt2_textsize = size # which can be nil, signifying no limit
          @lt2_textpos = 0
        end
      end

      # Alias for #set_text_mode, added for back-compatibility with LineAndTextProtocol.
      def set_binary_mode size=nil
        set_text_mode size
      end

      # In case of a dropped connection, we'll send a partial buffer to user code
      # when in sized text mode. User overrides of #receive_binary_data need to
      # be aware that they may get a short buffer.
      def unbind
        @lt2_mode ||= nil
        if @lt2_mode == :text and @lt2_textpos > 0
          receive_binary_data @lt2_textbuffer.join
        end
      end

      # Stub. Should be subclassed by user code.
      def receive_line ln
        # no-op
      end

      # Stub. Should be subclassed by user code.
      def receive_binary_data data
        # no-op
      end

      # Stub. Should be subclassed by user code.
      # This is called when transitioning internally from text mode
      # back to line mode. Useful when client code doesn't want
      # to keep track of how much data it's received.
      def receive_end_of_binary_data
        # no-op
      end
    end
  end
end
