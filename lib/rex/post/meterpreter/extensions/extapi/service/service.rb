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

  def initialize(client)
    @client = client
  end

  # Enumerate all the services on the target.
  def enumerate
    request = Packet.create_request('extapi_service_enum')
    response = client.send_request(request)

    services = []

    response.each(TLV_TYPE_EXT_SERVICE_ENUM_GROUP) { |s|
      services << {
        :name         => s.get_tlv_value(TLV_TYPE_EXT_SERVICE_ENUM_NAME),
        :display      => s.get_tlv_value(TLV_TYPE_EXT_SERVICE_ENUM_DISPLAYNAME),
        :pid          => s.get_tlv_value(TLV_TYPE_EXT_SERVICE_ENUM_PID),
        :status       => s.get_tlv_value(TLV_TYPE_EXT_SERVICE_ENUM_STATUS),
        :interactive  => s.get_tlv_value(TLV_TYPE_EXT_SERVICE_ENUM_INTERACTIVE)
      }
    }

    return services.sort_by { |s| s[:name].upcase }
  end

  # Query some detailed parameters about a particular service.
  def query(service_name)
    request = Packet.create_request('extapi_service_query')
    request.add_tlv(TLV_TYPE_EXT_SERVICE_ENUM_NAME, service_name)

    response = client.send_request(request)

    detail = {
      :starttype   => response.get_tlv_value(TLV_TYPE_EXT_SERVICE_QUERY_STARTTYPE),
      :display     => response.get_tlv_value(TLV_TYPE_EXT_SERVICE_QUERY_DISPLAYNAME),
      :startname   => response.get_tlv_value(TLV_TYPE_EXT_SERVICE_QUERY_STARTNAME),
      :path        => response.get_tlv_value(TLV_TYPE_EXT_SERVICE_QUERY_PATH),
      :logroup     => response.get_tlv_value(TLV_TYPE_EXT_SERVICE_QUERY_LOADORDERGROUP),
      :interactive => response.get_tlv_value(TLV_TYPE_EXT_SERVICE_QUERY_INTERACTIVE),
      :dacl        => response.get_tlv_value(TLV_TYPE_EXT_SERVICE_QUERY_DACL)
    }

    return detail
  end

  attr_accessor :client

end

end; end; end; end; end; end
