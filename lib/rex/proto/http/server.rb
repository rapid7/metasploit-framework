# -*- coding: binary -*-
require 'rex/socket'
require 'rex/proto/http'
require 'rex/proto/http/handler'

module Rex
module Proto
module Http

###
#
# Runtime extension of the HTTP clients that connect to the server.
#
###
module ServerClient

  #
  # Initialize a new request instance.
  #
  def init_cli(server)
    self.request   = Request.new
    self.server    = server
    self.keepalive = false
  end

  #
  # Resets the parsing state.
  #
  def reset_cli
    self.request.reset
  end

  #
  # Transmits a response and adds the appropriate headers.
  #
  def send_response(response)
    # Set the connection to close or keep-alive depending on what the client
    # can support.
    response['Connection'] = (keepalive) ? 'Keep-Alive' : 'close'

    # Add any other standard response headers.
    server.add_response_headers(response)

    # Send it off.
    put(response.to_s)
  end

  #
  # The current request context.
  #
  attr_accessor :request
  #
  # Boolean that indicates whether or not the connection supports keep-alive.
  #
  attr_accessor :keepalive
  #
  # A reference to the server the client is associated with.
  #
  attr_accessor :server

end

###
#
# Acts as an HTTP server, processing requests and dispatching them to
# registered procs.  Some of this server was modeled after webrick.
#
###
class Server

  include Proto

  #
  # A hash that associated a file extension with a mime type for use as the
  # content type of responses.
  #
  ExtensionMimeTypes =
    {
      "rhtml" => "text/html",
      "html"  => "text/html",
      "htm"   => "text/htm",
      "jpg"   => "image/jpeg",
      "jpeg"  => "image/jpeg",
      "gif"   => "image/gif",
      "png"   => "image/png",
      "bmp"   => "image/bmp",
      "txt"   => "text/plain",
      "css"   => "text/css",
      "ico"   => "image/x-icon",
    }

  #
  # The default server name that will be returned in the Server attribute of
  # a response.
  #
  DefaultServer = "Rex"

  #
  # Initializes an HTTP server as listening on the provided port and
  # hostname.
  #
  def initialize(port = 80, listen_host = '0.0.0.0', ssl = false, context = {},
                 comm = nil, ssl_cert = nil, ssl_compression = false,
                 ssl_cipher = nil)
    self.listen_host     = listen_host
    self.listen_port     = port
    self.ssl             = ssl
    self.context         = context
    self.comm            = comm
    self.ssl_cert        = ssl_cert
    self.ssl_compression = ssl_compression
    self.ssl_cipher      = ssl_cipher
    self.listener        = nil
    self.resources       = {}
    self.server_name     = DefaultServer
  end

  # More readable inspect that only shows the url and resources
  # @return [String]
  def inspect
    resources_str = resources.keys.map{|r| r.inspect }.join ", "

    "#<#{self.class} http#{ssl ? "s" : ""}://#{listen_host}:#{listen_port} [ #{resources_str} ]>"
  end

  #
  # Returns the hardcore alias for the HTTP service
  #
  def self.hardcore_alias(*args)
    "#{(args[0] || '')}#{(args[1] || '')}"
  end

  #
  # HTTP server.
  #
  def alias
    super || "HTTP Server"
  end

  #
  # Listens on the defined port and host and starts monitoring for clients.
  #
  def start

    self.listener = Rex::Socket::TcpServer.create(
      'LocalHost' => self.listen_host,
      'LocalPort' => self.listen_port,
      'Context'   => self.context,
      'SSL'       => self.ssl,
      'SSLCert'   => self.ssl_cert,
      'SSLCompression' => self.ssl_compression,
      'SSLCipher' => self.ssl_cipher,
      'Comm'      => self.comm
    )

    # Register callbacks
    self.listener.on_client_connect_proc = Proc.new { |cli|
      on_client_connect(cli)
    }
    self.listener.on_client_data_proc = Proc.new { |cli|
      on_client_data(cli)
    }

    self.listener.start
  end

  #
  # Terminates the monitor thread and turns off the listener.
  #
  def stop
    self.listener.stop
    self.listener.close
  end


  #
  # Waits for the HTTP service to terminate
  #
  def wait
    self.listener.wait if self.listener
  end

  #
  # Closes the supplied client, if valid.
  #
  def close_client(cli)
    listener.close_client(cli)
  end

  #
  # Mounts a directory or resource as being serviced by the supplied handler.
  #
  def mount(root, handler, long_call = false, *args)
    resources[root] = [ handler, long_call, args ]
  end

  #
  # Remove the mount point.
  #
  def unmount(root)
    resources.delete(root)
  end

  #
  # Adds a resource handler, such as one for /, which will be called whenever
  # the resource is requested.  The ``opts'' parameter can have any of the
  # following:
  #
  # Proc      (proc) - The procedure to call when a request comes in for this resource.
  # LongCall  (bool) - Hints to the server that this resource may have long
  #                    request processing times.
  #
  def add_resource(name, opts)
    if (resources[name])
      raise RuntimeError,
        "The supplied resource '#{name}' is already added.", caller
    end

    # If a procedure was passed, mount the resource with it.
    if (opts['Proc'])
      mount(name, Handler::Proc, false, opts['Proc'], opts['VirtualDirectory'])
    else
      raise ArgumentError, "You must specify a procedure."
    end
  end

  #
  # Removes the supplied resource handler.
  #
  def remove_resource(name)
    self.resources.delete(name)
  end

  #
  # Adds Server headers and stuff.
  #
  def add_response_headers(resp)
    resp['Server'] = self.server_name if not resp['Server']
  end

  #
  # Returns the mime type associated with the supplied file.  Right now the
  # set of mime types is fairly limited.
  #
  def mime_type(file)
    type = nil

    if (file =~ /\.(.+?)$/)
      type = ExtensionMimeTypes[$1.downcase]
    end

    type || "text/plain"
  end

  #
  # Sends a 404 error to the client for a given request.
  #
  def send_e404(cli, request)
    resp = Response::E404.new

    resp['Content-Type'] = 'text/html'

    resp.body =
      "<html><head>" +
      "<title>404 Not Found</title>" +
      "</head><body>" +
      "<h1>Not found</h1>" +
      "The requested URL #{html_escape(request.resource)} was not found on this server.<p><hr>" +
      "</body></html>"

    # Send the response to the client like what
    cli.send_response(resp)
  end

  attr_accessor :listen_port, :listen_host, :server_name, :context, :comm
  attr_accessor :ssl, :ssl_cert, :ssl_compression, :ssl_cipher
  attr_accessor :listener, :resources

protected

  #
  # Extends new clients with the ServerClient module and initializes them.
  #
  def on_client_connect(cli)
    cli.extend(ServerClient)

    cli.init_cli(self)
  end

  #
  # Processes data coming in from a client.
  #
  def on_client_data(cli)
    begin
      data = cli.read(65535)

      raise ::EOFError if not data
      raise ::EOFError if data.empty?

      case cli.request.parse(data)
        when Packet::ParseCode::Completed
          dispatch_request(cli, cli.request)
          cli.reset_cli

        when Packet::ParseCode::Partial
          # Return and wait for the on_client_data handler to be called again
          # The Request object tracks the state of the request for us
          return

        when Packet::ParseCode::Error
          close_client(cli)
      end
    rescue EOFError
      if (cli.request.completed?)
        dispatch_request(cli, cli.request)

        cli.reset_cli
      end

      close_client(cli)
    end
  end

  #
  # Dispatches the supplied request for a given connection.
  #
  def dispatch_request(cli, request)
    # Is the client requesting keep-alive?
    if ((request['Connection']) and
       (request['Connection'].downcase == 'Keep-Alive'.downcase))
      cli.keepalive = true
    end

    # Search for the resource handler for the requested URL.  This is pretty
    # inefficient right now, but we can spruce it up later.
    p    = nil
    len  = 0
    root = nil

    resources.each_pair { |k, val|
      if (request.resource =~ /^#{k}/ and k.length > len)
        p    = val
        len  = k.length
        root = k
      end
    }

    if (p)
      # Create an instance of the handler for this resource
      handler = p[0].new(self, *p[2])

      # If the handler class requires a relative resource...
      if (handler.relative_resource_required?)
        # Substituted the mount point root in the request to make things
        # relative to the mount point.
        request.relative_resource = request.resource.gsub(/^#{root}/, '')
        request.relative_resource = '/' + request.relative_resource if (request.relative_resource !~ /^\//)
      end


      # If we found the resource handler for this resource, call its
      # procedure.
      if (p[1] == true)
        Rex::ThreadFactory.spawn("HTTPServerRequestHandler", false) {
          handler.on_request(cli, request)
        }
      else
        handler.on_request(cli, request)
      end
    else
      elog("Failed to find handler for resource: #{request.resource}",
        LogSource)

      send_e404(cli, request)
    end

    # If keep-alive isn't enabled for this client, close the connection
    if (cli.keepalive == false)
      close_client(cli)
    end
  end

end

end
end
end

