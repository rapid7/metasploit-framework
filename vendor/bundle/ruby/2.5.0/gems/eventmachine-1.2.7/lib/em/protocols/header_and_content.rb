#--
#
# Author:: Francis Cianfrocca (gmail: blackhedd)
# Homepage::  http://rubyeventmachine.com
# Date:: 15 Nov 2006
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

    # === Usage
    #
    #  class RequestHandler < EM::P::HeaderAndContentProtocol
    #    def receive_request headers, content
    #      p [:request, headers, content]
    #    end
    #  end
    #
    #  EM.run{
    #    EM.start_server 'localhost', 80, RequestHandler
    #  }
    #
    #--
    # Originally, this subclassed LineAndTextProtocol, which in
    # turn relies on BufferedTokenizer, which doesn't gracefully
    # handle the transitions between lines and binary text.
    # Changed 13Sep08 by FCianfrocca.
    class HeaderAndContentProtocol < Connection
      include LineText2

      ContentLengthPattern = /Content-length:\s*(\d+)/i

      def initialize *args
        super
        init_for_request
      end

      def receive_line line
        case @hc_mode
        when :discard_blanks
          unless line == ""
            @hc_mode = :headers
            receive_line line
          end
        when :headers
          if line == ""
            raise "unrecognized state" unless @hc_headers.length > 0
            if respond_to?(:receive_headers)
              receive_headers @hc_headers
            end
            # @hc_content_length will be nil, not 0, if there was no content-length header.
            if @hc_content_length.to_i > 0
              set_binary_mode @hc_content_length
            else
              dispatch_request
            end
          else
            @hc_headers << line
            if ContentLengthPattern =~ line
              # There are some attacks that rely on sending multiple content-length
              # headers. This is a crude protection, but needs to become tunable.
              raise "extraneous content-length header" if @hc_content_length
              @hc_content_length = $1.to_i
            end
            if @hc_headers.length == 1 and respond_to?(:receive_first_header_line)
              receive_first_header_line line
            end
          end
        else
          raise "internal error, unsupported mode"
        end
      end

      def receive_binary_data text
        @hc_content = text
        dispatch_request
      end

      def dispatch_request
        if respond_to?(:receive_request)
          receive_request @hc_headers, @hc_content
        end
        init_for_request
      end
      private :dispatch_request

      def init_for_request
        @hc_mode = :discard_blanks
        @hc_headers = []
        # originally was @hc_headers ||= []; @hc_headers.clear to get a performance
        # boost, but it's counterproductive because a subclassed handler will have to
        # call dup to use the header array we pass in receive_headers.

        @hc_content_length = nil
        @hc_content = ""
      end
      private :init_for_request

      # Basically a convenience method. We might create a subclass that does this
      # automatically. But it's such a performance killer.
      def headers_2_hash hdrs
        self.class.headers_2_hash hdrs
      end

      class << self
        def headers_2_hash hdrs
          hash = {}
          hdrs.each {|h|
            if /\A([^\s:]+)\s*:\s*/ =~ h
              tail = $'.dup
              hash[ $1.downcase.gsub(/-/,"_").intern ] = tail
            end
          }
          hash
        end
      end

    end
  end
end
