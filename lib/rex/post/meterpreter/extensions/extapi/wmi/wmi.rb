# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Extapi
module Wmi

###
#
# This meterpreter extension contains extended API functions for
# performing WMI queries.
#
###
class Wmi

  def initialize(client)
    @client = client
  end

  #
  # Perform a generic wmi query against the target machine.
  #
  # @param query [String] The WMI query string.
  # @param root [String] Specify root to target, otherwise defaults
  #   to 'root\cimv2'
  #
  # @return [Hash] Array of field names with associated values.
  #
  def query(query, root = nil)
    request = Packet.create_request('extapi_wmi_query')

    request.add_tlv(TLV_TYPE_EXT_WMI_DOMAIN, root) unless root.to_s.strip.empty?
    request.add_tlv(TLV_TYPE_EXT_WMI_QUERY, query)

    response = client.send_request(request)

    # Bomb out with the right error messa
    error_msg = response.get_tlv_value(TLV_TYPE_EXT_WMI_ERROR)
    raise error_msg if error_msg

    fields = []
    fields_tlv = response.get_tlv(TLV_TYPE_EXT_WMI_FIELDS)

    # If we didn't get any fields back, then we didn't get any results.
    # The reason is because without results, we don't know which fields
    # were requested in the first place
    return nil unless fields_tlv

    fields_tlv.each(TLV_TYPE_EXT_WMI_FIELD) { |f|
      fields << f.value
    }

    values = []
    response.each(TLV_TYPE_EXT_WMI_VALUES) { |r|
      value = []
      r.each(TLV_TYPE_EXT_WMI_VALUE) { |v|
        value << v.value
      }
      values << value
    }

    return {
      :fields  => fields,
      :values => values
    }
  end

  attr_accessor :client

end

end; end; end; end; end; end

