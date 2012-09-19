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
    #  EM.run{
    #    conn = EM::Protocols::HttpClient2.connect 'google.com', 80
    #
    #    req = conn.get('/')
    #    req.callback{ |response|
    #      p(response.status)
    #      p(response.headers)
    #      p(response.content)
    #    }
    #  }
    class HttpClient2 < Connection
      include LineText2
      
      def initialize
        @authorization = nil
        @closed = nil
        @requests = nil
      end

      class Request # :nodoc:
        include Deferrable

        attr_reader :version
        attr_reader :status
        attr_reader :header_lines
        attr_reader :headers
        attr_reader :content
        attr_reader :internal_error

        def initialize conn, args
          @conn = conn
          @args = args
          @header_lines = []
          @headers = {}
          @blanks = 0
          @chunk_trailer = nil
          @chunking = nil
        end

        def send_request
          az = @args[:authorization] and az = "Authorization: #{az}\r\n"

          r = [
            "#{@args[:verb]} #{@args[:uri]} HTTP/#{@args[:version] || "1.1"}\r\n",
            "Host: #{@args[:host_header] || "_"}\r\n",
            az || "",
              "\r\n"
          ]
          @conn.send_data r.join
        end


        #--
        #
        def receive_line ln
          if @chunk_trailer
            receive_chunk_trailer(ln)
          elsif @chunking
            receive_chunk_header(ln)
          else
            receive_header_line(ln)
          end
        end

        #--
        #
        def receive_chunk_trailer ln
          if ln.length == 0
            @conn.pop_request
            succeed(self)
          else
            p "Received chunk trailer line"
          end
        end

        #--
        # Allow up to ten blank lines before we get a real response line.
        # Allow no more than 100 lines in the header.
        #
        def receive_header_line ln
          if ln.length == 0
            if @header_lines.length > 0
              process_header
            else
              @blanks += 1
              if @blanks > 10
                @conn.close_connection
              end
            end
          else
            @header_lines << ln
            if @header_lines.length > 100
              @internal_error = :bad_header
              @conn.close_connection
            end
          end
        end

        #--
        # Cf RFC 2616 pgh 3.6.1 for the format of HTTP chunks.
        #
        def receive_chunk_header ln
          if ln.length > 0
            chunksize = ln.to_i(16)
            if chunksize > 0
              @conn.set_text_mode(ln.to_i(16))
            else
              @content = @content ? @content.join : ''
              @chunk_trailer = true
            end
          else
            # We correctly come here after each chunk gets read.
            # p "Got A BLANK chunk line"
          end

        end


        #--
        # We get a single chunk. Append it to the incoming content and switch back to line mode.
        #
        def receive_chunked_text text
          # p "RECEIVED #{text.length} CHUNK"
          (@content ||= []) << text
        end


        #--
        # TODO, inefficient how we're handling this. Part of it is done so as to
        # make sure we don't have problems in detecting chunked-encoding, content-length,
        # etc.
        #
        HttpResponseRE = /\AHTTP\/(1.[01]) ([\d]{3})/i
        ClenRE = /\AContent-length:\s*(\d+)/i
        ChunkedRE = /\ATransfer-encoding:\s*chunked/i
        ColonRE = /\:\s*/

        def process_header
          unless @header_lines.first =~ HttpResponseRE
            @conn.close_connection
            @internal_error = :bad_request
          end
          @version = $1.dup
          @status = $2.dup.to_i

          clen = nil
          chunks = nil
          @header_lines.each_with_index do |e,ix|
            if ix > 0
              hdr,val = e.split(ColonRE,2)
              (@headers[hdr.downcase] ||= []) << val
            end

            if clen == nil and e =~ ClenRE
              clen = $1.dup.to_i
            end
            if e =~ ChunkedRE
              chunks = true
            end
          end

          if clen
            # If the content length is zero we should not call set_text_mode,
            # because a value of zero will make it wait forever, hanging the
            # connection. Just return success instead, with empty content.
            if clen == 0 then
              @content = ""
              @conn.pop_request
              succeed(self)
            else
              @conn.set_text_mode clen
            end
          elsif chunks
            @chunking = true
          else
            # Chunked transfer, multipart, or end-of-connection.
            # For end-of-connection, we need to go the unbind
            # method and suppress its desire to fail us.
            p "NO CLEN"
            p @args[:uri]
            p @header_lines
            @internal_error = :unsupported_clen
            @conn.close_connection
          end
        end
        private :process_header


        def receive_text text
          @chunking ? receive_chunked_text(text) : receive_sized_text(text)
        end

        #--
        # At the present time, we only handle contents that have a length
        # specified by the content-length header.
        #
        def receive_sized_text text
          @content = text
          @conn.pop_request
          succeed(self)
        end
      end

      # Make a connection to a remote HTTP server.
      # Can take either a pair of arguments (which will be interpreted as
      # a hostname/ip-address and a port), or a hash.
      # If the arguments are a hash, then supported values include:
      #  :host => a hostname or ip-address
      #  :port => a port number
      #  :ssl => true to enable ssl
      def self.connect *args
        if args.length == 2
          args = {:host=>args[0], :port=>args[1]}
        else
          args = args.first
        end

        h,prt,ssl = args[:host], Integer(args[:port]), (args[:tls] || args[:ssl])
        conn = EM.connect( h, prt, self )
        conn.start_tls if ssl
        conn.set_default_host_header( h, prt, ssl )
        conn
      end

      # Get a url
      #
      #  req = conn.get(:uri => '/')
      #  req.callback{|response| puts response.content }
      #
      def get args
        if args.is_a?(String)
          args = {:uri=>args}
        end
        args[:verb] = "GET"
        request args
      end

      # Post to a url
      #
      #  req = conn.post('/data')
      #  req.callback{|response| puts response.content }
      #--
      # XXX there's no way to supply a POST body.. wtf?
      def post args
        if args.is_a?(String)
          args = {:uri=>args}
        end
        args[:verb] = "POST"
        request args
      end

      # :stopdoc:

      #--
      # Compute and remember a string to be used as the host header in HTTP requests
      # unless the user overrides it with an argument to #request.
      #
      def set_default_host_header host, port, ssl
        if (ssl and port != 443) or (!ssl and port != 80)
          @host_header = "#{host}:#{port}"
        else
          @host_header = host
        end
      end


      def post_init
        super
        @connected = EM::DefaultDeferrable.new
      end

      def connection_completed
        super
        @connected.succeed
      end

      #--
      # All pending requests, if any, must fail.
      # We might come here without ever passing through connection_completed
      # in case we can't connect to the server. We'll also get here when the
      # connection closes (either because the server closes it, or we close it
      # due to detecting an internal error or security violation).
      # In either case, run down all pending requests, if any, and signal failure
      # on them.
      #
      # Set and remember a flag (@closed) so we can immediately fail any
      # subsequent requests.
      #
      def unbind
        super
        @closed = true
        (@requests || []).each {|r| r.fail}
      end

      def request args
        args[:host_header] = @host_header unless args.has_key?(:host_header)
        args[:authorization] = @authorization unless args.has_key?(:authorization)
        r = Request.new self, args
        if @closed
          r.fail
        else
          (@requests ||= []).unshift r
          @connected.callback {r.send_request}
        end
        r
      end

      def receive_line ln
        if req = @requests.last
          req.receive_line ln
        else
          p "??????????"
          p ln
        end

      end
      def receive_binary_data text
        @requests.last.receive_text text
      end

      #--
      # Called by a Request object when it completes.
      #
      def pop_request
        @requests.pop
      end

      # :startdoc:
    end


=begin
  class HttpClient2x < Connection
    include LineText2

    # TODO: Make this behave appropriate in case a #connect fails.
    # Currently, this produces no errors.

    # Make a connection to a remote HTTP server.
    # Can take either a pair of arguments (which will be interpreted as
    # a hostname/ip-address and a port), or a hash.
    # If the arguments are a hash, then supported values include:
    #  :host => a hostname or ip-address;
    #  :port => a port number
    #--
    # TODO, support optional encryption arguments like :ssl
    def self.connect *args
      if args.length == 2
        args = {:host=>args[0], :port=>args[1]}
      else
        args = args.first
      end

      h,prt = args[:host],Integer(args[:port])
      EM.connect( h, prt, self, h, prt )
    end


    #--
    # Sugars a connection that makes a single request and then
    # closes the connection. Matches the behavior and the arguments
    # of the original implementation of class HttpClient.
    #
    # Intended primarily for back compatibility, but the idiom
    # is probably useful so it's not deprecated.
    # We return a Deferrable, as did the original implementation.
    #
    # Because we're improving the way we deal with errors and exceptions
    # (specifically, HTTP response codes other than 2xx will trigger the
    # errback rather than the callback), this may break some existing code.
    #
    def self.request args
      c = connect args
    end

    #--
    # Requests can be pipelined. When we get a request, add it to the
    # front of a queue as an array. The last element of the @requests
    # array is always the oldest request received. Each element of the
    # @requests array is a two-element array consisting of a hash with
    # the original caller's arguments, and an initially-empty Ostruct
    # containing the data we retrieve from the server's response.
    # Maintain the instance variable @current_response, which is the response
    # of the oldest pending request. That's just to make other code a little
    # easier. If the variable doesn't exist when we come here, we're
    # obviously the first request being made on the connection.
    #
    # The reason for keeping this method private (and requiring use of the
    # convenience methods #get, #post, #head, etc) is to avoid the small
    # performance penalty of canonicalizing the verb.
    #
    def request args
      d = EventMachine::DefaultDeferrable.new

      if @closed
        d.fail
        return d
      end

      o = OpenStruct.new
      o.deferrable = d
      (@requests ||= []).unshift [args, o]
      @current_response ||= @requests.last.last
      @connected.callback {
        az = args[:authorization] and az = "Authorization: #{az}\r\n"

        r = [
          "#{args[:verb]} #{args[:uri]} HTTP/#{args[:version] || "1.1"}\r\n",
          "Host: #{args[:host_header] || @host_header}\r\n",
          az || "",
          "\r\n"
        ]
        p r
        send_data r.join
      }
      o.deferrable
    end
    private :request

    def get args
      if args.is_a?(String)
        args = {:uri=>args}
      end
      args[:verb] = "GET"
      request args
    end

    def initialize host, port
      super
      @host_header = "#{host}:#{port}"
    end
    def post_init
      super
      @connected = EM::DefaultDeferrable.new
    end


    def connection_completed
      super
      @connected.succeed
    end

    #--
    # Make sure to throw away any leftover incoming data if we've
    # been closed due to recognizing an error.
    #
    # Generate an internal error if we get an unreasonable number of
    # header lines. It could be malicious.
    #
    def receive_line ln
      p ln
      return if @closed

      if ln.length > 0
        (@current_response.headers ||= []).push ln
        abort_connection if @current_response.headers.length > 100
      else
        process_received_headers
      end
    end

    #--
    # We come here when we've seen all the headers for a particular request.
    # What we do next depends on the response line (which should be the
    # first line in the header set), and whether there is content to read.
    # We may transition into a text-reading state to read content, or
    # we may abort the connection, or we may go right back into parsing
    # responses for the next response in the chain.
    #
    # We make an ASSUMPTION that the first line is an HTTP response.
    # Anything else produces an error that aborts the connection.
    # This may not be enough, because it may be that responses to pipelined
    # requests will come with a blank-line delimiter.
    #
    # Any non-2xx response will be treated as a fatal error, and abort the
    # connection. We will set up the status and other response parameters.
    # TODO: we will want to properly support 1xx responses, which some versions
    # of IIS copiously generate.
    # TODO: We need to give the option of not aborting the connection with certain
    # non-200 responses, in order to work with NTLM and other authentication
    # schemes that work at the level of individual connections.
    #
    # Some error responses will get sugarings. For example, we'll return the
    # Location header in the response in case of a 301/302 response.
    #
    # Possible dispositions here:
    # 1) No content to read (either content-length is zero or it's a HEAD request);
    # 2) Switch to text mode to read a specific number of bytes;
    # 3) Read a chunked or multipart response;
    # 4) Read till the server closes the connection.
    #
    # Our reponse to the client can be either to wait till all the content
    # has been read and then to signal caller's deferrable, or else to signal
    # it when we finish the processing the headers and then expect the caller
    # to have given us a block to call as the content comes in. And of course
    # the latter gets stickier with chunks and multiparts.
    #
    HttpResponseRE = /\AHTTP\/(1.[01]) ([\d]{3})/i
    ClenRE = /\AContent-length:\s*(\d+)/i
    def process_received_headers
      abort_connection unless @current_response.headers.first =~ HttpResponseRE
      @current_response.version = $1.dup
      st = $2.dup
      @current_response.status = st.to_i
      abort_connection unless st[0,1] == "2"

      clen = nil
      @current_response.headers.each do |e|
        if clen == nil and e =~ ClenRE
          clen = $1.dup.to_i
        end
      end

      if clen
        set_text_mode clen
      end
    end
    private :process_received_headers


    def receive_binary_data text
      @current_response.content = text
      @current_response.deferrable.succeed @current_response
      @requests.pop
      @current_response = (@requests.last || []).last
      set_line_mode
    end



    # We've received either a server error or an internal error.
    # Close the connection and abort any pending requests.
    #--
    # When should we call close_connection? It will cause #unbind
    # to be fired. Should the user expect to see #unbind before
    # we call #receive_http_error, or the other way around?
    #
    # Set instance variable @closed. That's used to inhibit further
    # processing of any inbound data after an error has been recognized.
    #
    # We shouldn't have to worry about any leftover outbound data,
    # because we call close_connection (not close_connection_after_writing).
    # That ensures that any pipelined requests received after an error
    # DO NOT get streamed out to the server on this connection.
    # Very important. TODO, write a unit-test to establish that behavior.
    #
    def abort_connection
      close_connection
      @closed = true
      @current_response.deferrable.fail( @current_response )
    end


    #------------------------
    # Below here are user-overridable methods.

  end
=end
  end
end
