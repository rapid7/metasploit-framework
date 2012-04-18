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



module EventMachine
  module Protocols

    # === Usage
    #
    #  EventMachine.run {
    #    http = EventMachine::Protocols::HttpClient.request(
    #      :host => server,
    #      :port => 80,
    #      :request => "/index.html",
    #      :query_string => "parm1=value1&parm2=value2"
    #    )
    #    http.callback {|response|
    #      puts response[:status]
    #      puts response[:headers]
    #      puts response[:content]
    #    }
    #  }
    #--
    # TODO:
    # Add streaming so we can support enormous POSTs. Current max is 20meg.
    # Timeout for connections that run too long or hang somewhere in the middle.
    # Persistent connections (HTTP/1.1), may need a associated delegate object.
    # DNS: Some way to cache DNS lookups for hostnames we connect to. Ruby's
    # DNS lookups are unbelievably slow.
    # HEAD requests.
    # Chunked transfer encoding.
    # Convenience methods for requests. get, post, url, etc.
    # SSL.
    # Handle status codes like 304, 100, etc.
    # Refactor this code so that protocol errors all get handled one way (an exception?),
    # instead of sprinkling set_deferred_status :failed calls everywhere.
    class HttpClient < Connection
      include EventMachine::Deferrable

      MaxPostContentLength = 20 * 1024 * 1024

      # === Arg list
      # :host => 'ip/dns', :port => fixnum, :verb => 'GET', :request => 'path',
      # :basic_auth => {:username => '', :password => ''}, :content => 'content',
      # :contenttype => 'text/plain', :query_string => '', :host_header => '',
      # :cookie => ''
      def self.request( args = {} )
        args[:port] ||= 80
        EventMachine.connect( args[:host], args[:port], self ) {|c|
          # According to the docs, we will get here AFTER post_init is called.
          c.instance_eval {@args = args}
        }
      end

      def post_init
        @start_time = Time.now
        @data = ""
        @read_state = :base
      end

      # We send the request when we get a connection.
      # AND, we set an instance variable to indicate we passed through here.
      # That allows #unbind to know whether there was a successful connection.
      # NB: This naive technique won't work when we have to support multiple
      # requests on a single connection.
      def connection_completed
        @connected = true
        send_request @args
      end

      def send_request args
        args[:verb] ||= args[:method] # Support :method as an alternative to :verb.
        args[:verb] ||= :get # IS THIS A GOOD IDEA, to default to GET if nothing was specified?

        verb = args[:verb].to_s.upcase
        unless ["GET", "POST", "PUT", "DELETE", "HEAD"].include?(verb)
          set_deferred_status :failed, {:status => 0} # TODO, not signalling the error type
          return # NOTE THE EARLY RETURN, we're not sending any data.
        end

        request = args[:request] || "/"
        unless request[0,1] == "/"
          request = "/" + request
        end

        qs = args[:query_string] || ""
        if qs.length > 0 and qs[0,1] != '?'
          qs = "?" + qs
        end

        version = args[:version] || "1.1"

        # Allow an override for the host header if it's not the connect-string.
        host = args[:host_header] || args[:host] || "_"
        # For now, ALWAYS tuck in the port string, although we may want to omit it if it's the default.
        port = args[:port]

        # POST items.
        postcontenttype = args[:contenttype] || "application/octet-stream"
        postcontent = args[:content] || ""
        raise "oversized content in HTTP POST" if postcontent.length > MaxPostContentLength

        # ESSENTIAL for the request's line-endings to be CRLF, not LF. Some servers misbehave otherwise.
        # TODO: We ASSUME the caller wants to send a 1.1 request. May not be a good assumption.
        req = [
          "#{verb} #{request}#{qs} HTTP/#{version}",
          "Host: #{host}:#{port}",
          "User-agent: Ruby EventMachine",
        ]

          if verb == "POST" || verb == "PUT"
            req << "Content-type: #{postcontenttype}"
            req << "Content-length: #{postcontent.length}"
          end

          # TODO, this cookie handler assumes it's getting a single, semicolon-delimited string.
          # Eventually we will want to deal intelligently with arrays and hashes.
          if args[:cookie]
            req << "Cookie: #{args[:cookie]}"
          end

          # Basic-auth stanza contributed by Matt Murphy.
          if args[:basic_auth]
            basic_auth_string = ["#{args[:basic_auth][:username]}:#{args[:basic_auth][:password]}"].pack('m').strip.gsub(/\n/,'')
            req << "Authorization: Basic #{basic_auth_string}"
          end

          req << ""
          reqstring = req.map {|l| "#{l}\r\n"}.join
          send_data reqstring

          if verb == "POST" || verb == "PUT"
            send_data postcontent
          end
      end


      def receive_data data
        while data and data.length > 0
          case @read_state
          when :base
            # Perform any per-request initialization here and don't consume any data.
            @data = ""
            @headers = []
            @content_length = nil # not zero
            @content = ""
            @status = nil
            @read_state = :header
            @connection_close = nil
          when :header
            ary = data.split( /\r?\n/m, 2 )
            if ary.length == 2
              data = ary.last
              if ary.first == ""
                if (@content_length and @content_length > 0) || @connection_close
                  @read_state = :content
                else
                  dispatch_response
                  @read_state = :base
                end
              else
                @headers << ary.first
                if @headers.length == 1
                  parse_response_line
                elsif ary.first =~ /\Acontent-length:\s*/i
                  # Only take the FIRST content-length header that appears,
                  # which we can distinguish because @content_length is nil.
                  # TODO, it's actually a fatal error if there is more than one
                  # content-length header, because the caller is presumptively
                  # a bad guy. (There is an exploit that depends on multiple
                  # content-length headers.)
                  @content_length ||= $'.to_i
                elsif ary.first =~ /\Aconnection:\s*close/i
                  @connection_close = true
                end
              end
            else
              @data << data
              data = ""
            end
          when :content
            # If there was no content-length header, we have to wait until the connection
            # closes. Everything we get until that point is content.
            # TODO: Must impose a content-size limit, and also must implement chunking.
            # Also, must support either temporary files for large content, or calling
            # a content-consumer block supplied by the user.
            if @content_length
              bytes_needed = @content_length - @content.length
              @content += data[0, bytes_needed]
              data = data[bytes_needed..-1] || ""
              if @content_length == @content.length
                dispatch_response
                @read_state = :base
              end
            else
              @content << data
              data = ""
            end
          end
        end
      end


      # We get called here when we have received an HTTP response line.
      # It's an opportunity to throw an exception or trigger other exceptional
      # handling.
      def parse_response_line
        if @headers.first =~ /\AHTTP\/1\.[01] ([\d]{3})/
          @status = $1.to_i
        else
          set_deferred_status :failed, {
            :status => 0 # crappy way of signifying an unrecognized response. TODO, find a better way to do this.
          }
          close_connection
        end
      end
      private :parse_response_line

      def dispatch_response
        @read_state = :base
        set_deferred_status :succeeded, {
          :content => @content,
          :headers => @headers,
          :status => @status
        }
        # TODO, we close the connection for now, but this is wrong for persistent clients.
        close_connection
      end

      def unbind
        if !@connected
          set_deferred_status :failed, {:status => 0} # YECCCCH. Find a better way to signal no-connect/network error.
        elsif (@read_state == :content and @content_length == nil)
          dispatch_response
        end
      end
    end

  end
end