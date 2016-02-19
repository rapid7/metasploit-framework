# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Extapi
module Service

###
#
# This meterpreter extension contains extended API functions for
# querying and managing Windows services.
#
###
class Service

  SERVICE_OP_START   = 1
  SERVICE_OP_PAUSE   = 2
  SERVICE_OP_RESUME  = 3
  SERVICE_OP_STOP    = 4
  SERVICE_OP_RESTART = 5

  def initialize(client)
    @client = client
  end

  #
  # Enumerate all the services on the target.
  #
  def enumerate
    request = Packet.create_request('extapi_service_enum')
    response = client.send_request(request)

    services = []

    response.each(TLV_TYPE_EXT_SERVICE_ENUM_GROUP) do |s|
      services << {
        :name         => s.get_tlv_value(TLV_TYPE_EXT_SERVICE_ENUM_NAME),
        :display      => s.get_tlv_value(TLV_TYPE_EXT_SERVICE_ENUM_DISPLAYNAME),
        :pid          => s.get_tlv_value(TLV_TYPE_EXT_SERVICE_ENUM_PID),
        :status       => s.get_tlv_value(TLV_TYPE_EXT_SERVICE_ENUM_STATUS),
        :interactive  => s.get_tlv_value(TLV_TYPE_EXT_SERVICE_ENUM_INTERACTIVE)
      }
    end

    services.sort_by { |s| s[:name].upcase }
  end

  #
  # Query some detailed parameters about a particular service.
  #
  def query(service_name)
    request = Packet.create_request('extapi_service_query')
    request.add_tlv(TLV_TYPE_EXT_SERVICE_ENUM_NAME, service_name)

    response = client.send_request(request)

    {
      :starttype   => response.get_tlv_value(TLV_TYPE_EXT_SERVICE_QUERY_STARTTYPE),
      :display     => response.get_tlv_value(TLV_TYPE_EXT_SERVICE_QUERY_DISPLAYNAME),
      :startname   => response.get_tlv_value(TLV_TYPE_EXT_SERVICE_QUERY_STARTNAME),
      :path        => response.get_tlv_value(TLV_TYPE_EXT_SERVICE_QUERY_PATH),
      :logroup     => response.get_tlv_value(TLV_TYPE_EXT_SERVICE_QUERY_LOADORDERGROUP),
      :interactive => response.get_tlv_value(TLV_TYPE_EXT_SERVICE_QUERY_INTERACTIVE),
      :dacl        => response.get_tlv_value(TLV_TYPE_EXT_SERVICE_QUERY_DACL),
      :status      => response.get_tlv_value(TLV_TYPE_EXT_SERVICE_QUERY_STATUS)
    }
  end

  #
  # Control a single service
  #
  def control(service_name, op)
    if op.is_a? String
      case op.strip.downcase
      when "start"
        op = SERVICE_OP_START
      when "pause"
        op = SERVICE_OP_PAUSE
      when "resume"
        op = SERVICE_OP_RESUME
      when "stop"
        op = SERVICE_OP_STOP
      when "restart"
        op = SERVICE_OP_RESTART
      end
    end

    unless (op.is_a? Integer) && op >= SERVICE_OP_START && op <= SERVICE_OP_RESTART
      raise ArgumentError, "Invalid operation: #{op}"
    end

    request = Packet.create_request('extapi_service_control')
    request.add_tlv(TLV_TYPE_EXT_SERVICE_CTRL_NAME, service_name)
    request.add_tlv(TLV_TYPE_EXT_SERVICE_CTRL_OP, op)
    client.send_request(request)
  end

  attr_accessor :client

end

end; end; end; end; end; end
