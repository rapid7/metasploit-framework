# -*- coding: binary -*-
require 'rex/socket'


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

end
end
end
