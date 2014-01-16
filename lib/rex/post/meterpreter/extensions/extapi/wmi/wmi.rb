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
  # @param domain_name [String] Specify to target something other
  #   than 'cimv2'
  #
  # @returns [Hash] Array of field names with associated values.
  #
  def query(query, domain_name = nil)
    request = Packet.create_request('extapi_wmi_query')

    request.add_tlv(TLV_TYPE_EXT_WMI_DOMAIN, domain_name) unless domain_name.blank?
    request.add_tlv(TLV_TYPE_EXT_WMI_QUERY, query)

    response = client.send_request(request)

    fields = []
    fields_tlv = response.get_tlv(TLV_TYPE_EXT_WMI_FIELDS)
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

