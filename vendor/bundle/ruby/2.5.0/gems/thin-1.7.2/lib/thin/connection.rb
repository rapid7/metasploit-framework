require 'socket'

module Thin
  # Connection between the server and client.
  # This class is instanciated by EventMachine on each new connection
  # that is opened.
  class Connection < EventMachine::Connection
    include Logging

    # This is a template async response. N.B. Can't use string for body on 1.9
    AsyncResponse = [-1, {}, []].freeze

    # Rack application (adapter) served by this connection.
    attr_accessor :app

    # Backend to the server
    attr_accessor :backend

    # Current request served by the connection
    attr_accessor :request

    # Next response sent through the connection
    attr_accessor :response

    # Calling the application in a threaded allowing
    # concurrent processing of requests.
    attr_writer :threaded

    # Get the connection ready to process a request.
    def post_init
      @request  = Request.new
      @response = Response.new
    end

    # Called when data is received from the client.
    def receive_data(data)
      @idle = false
      trace data
      process if @request.parse(data)
    rescue InvalidRequest => e
      log_error("Invalid request", e)
      post_process Response::BAD_REQUEST
    end

    # Called when all data was received and the request
    # is ready to be processed.
    def process
      if threaded?
        @request.threaded = true
        EventMachine.defer { post_process(pre_process) }
      else
        @request.threaded = false
        post_process(pre_process)
      end
    end

    def ssl_verify_peer(cert)
      # In order to make the cert available later we have to have made at least
      # a show of verifying it.
      true
    end

    def pre_process
      # Add client info to the request env
      @request.remote_address = remote_address

      # Connection may be closed unless the App#call response was a [-1, ...]
      # It should be noted that connection objects will linger until this
      # callback is no longer referenced, so be tidy!
      @request.async_callback = method(:post_process)

      if @backend.ssl?
        @request.env["rack.url_scheme"] = "https"

        if cert = get_peer_cert
          @request.env['rack.peer_cert'] = cert
        end
      end

      # When we're under a non-async framework like rails, we can still spawn
      # off async responses using the callback info, so there's little point
      # in removing this.
      response = AsyncResponse
      catch(:async) do
        # Process the request calling the Rack adapter
        response = @app.call(@request.env)
      end
      response
    rescue Exception => e
      unexpected_error(e)
      # Pass through error response
      can_persist? && @request.persistent? ? Response::PERSISTENT_ERROR : Response::ERROR
    end

    def post_process(result)
      return unless result
      result = result.to_a

      # Status code -1 indicates that we're going to respond later (async).
      return if result.first == AsyncResponse.first

      @response.status, @response.headers, @response.body = *result

      log_error("Rack application returned nil body. " \
                "Probably you wanted it to be an empty string?") if @response.body.nil?

      # HEAD requests should not return a body.
      @response.skip_body! if @request.head?

      # Make the response persistent if requested by the client
      @response.persistent! if @request.persistent?

      # Send the response
      @response.each do |chunk|
        trace chunk
        send_data chunk
      end

    rescue Exception => e
      unexpected_error(e)
      # Close connection since we can't handle response gracefully
      close_connection
    ensure
      # If the body is being deferred, then terminate afterward.
      if @response.body.respond_to?(:callback) && @response.body.respond_to?(:errback)
        @response.body.callback { terminate_request }
        @response.body.errback  { terminate_request }
      else
        # Don't terminate the response if we're going async.
        terminate_request unless result && result.first == AsyncResponse.first
      end
    end

    # Logs information about an unexpected exceptional condition
    def unexpected_error(e)
      log_error("Unexpected error while processing request", e)
    end

    def close_request_response
      @request.async_close.succeed if @request.async_close
      @request.close  rescue nil
      @response.close rescue nil
    end

    # Does request and response cleanup (closes open IO streams and
    # deletes created temporary files).
    # Re-initializes response and request if client supports persistent
    # connection.
    def terminate_request
      unless persistent?
        close_connection_after_writing rescue nil
        close_request_response
      else
        close_request_response
        # Connection become idle but it's still open
        @idle = true
        # Prepare the connection for another request if the client
        # supports HTTP pipelining (persistent connection).
        post_init
      end
    end

    # Called when the connection is unbinded from the socket
    # and can no longer be used to process requests.
    def unbind
      @request.async_close.succeed if @request.async_close
      @response.body.fail if @response.body.respond_to?(:fail)
      @backend.connection_finished(self)
    end

    # Allows this connection to be persistent.
    def can_persist!
      @can_persist = true
    end

    # Return +true+ if this connection is allowed to stay open and be persistent.
    def can_persist?
      @can_persist
    end

    # Return +true+ if the connection must be left open
    # and ready to be reused for another request.
    def persistent?
      @can_persist && @response.persistent?
    end

    # Return +true+ if the connection is open but is not
    # processing any user requests
    def idle?
      @idle
    end

    # +true+ if <tt>app.call</tt> will be called inside a thread.
    # You can set all requests as threaded setting <tt>Connection#threaded=true</tt>
    # or on a per-request case returning +true+ in <tt>app.deferred?</tt>.
    def threaded?
      @threaded || (@app.respond_to?(:deferred?) && @app.deferred?(@request.env))
    end

    # IP Address of the remote client.
    def remote_address
      socket_address
    rescue Exception => e
      log_error('Could not infer remote address', e)
      nil
    end

    protected
      # Returns IP address of peer as a string.
      def socket_address
        peer = get_peername
        Socket.unpack_sockaddr_in(peer)[1] if peer
      end
  end
end
