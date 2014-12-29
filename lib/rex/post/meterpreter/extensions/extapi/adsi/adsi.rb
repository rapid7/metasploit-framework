# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Extapi
module Adsi

###
#
# This meterpreter extension contains extended API functions for
# querying and managing desktop windows.
#
###
class Adsi

  def initialize(client)
    @client = client
  end

  #
  # Perform a generic domain query against ADSI.
  #
  # @param domain_name [String] The FQDN of the target domain.
  # @param filter [String] The filter to apply to the query in
  #   LDAP format.
  # @param max_results [Integer] The maximum number of results
  #   to return.
  # @param page_size [Integer] The size of the page of results
  #   to return.
  # @param fields [Array] Array of string fields to return for
  #   each result found
  #
  # @return [Hash] Array of field names with associated results.
  #
  def domain_query(domain_name, filter, max_results, page_size, fields)
    request = Packet.create_request('extapi_adsi_domain_query')

    request.add_tlv(TLV_TYPE_EXT_ADSI_DOMAIN, domain_name)
    request.add_tlv(TLV_TYPE_EXT_ADSI_FILTER, filter)
    request.add_tlv(TLV_TYPE_EXT_ADSI_MAXRESULTS, max_results)
    request.add_tlv(TLV_TYPE_EXT_ADSI_PAGESIZE, page_size)

    fields.each do |f|
      request.add_tlv(TLV_TYPE_EXT_ADSI_FIELD, f)
    end

    response = client.send_request(request)

    results = extract_results(response)

    return {
      :fields  => fields,
      :results => results
    }
  end

  attr_accessor :client

protected

  #
  # Retrieve the results of the query from the response
  #   packet that was returned from Meterpreter.
  #
  # @param response [Packet] Reference to the received
  #   packet that was returned from Meterpreter.
  #
  # @return [Array[Array[[Hash]]] Collection of results from
  #   the ADSI query.
  #
  def extract_results(response)
    results = []

    response.each(TLV_TYPE_EXT_ADSI_RESULT) do |r|
      results << extract_values(r)
    end

    results
  end

  #
  # Extract a single row of results from a TLV group.
  #
  # @param tlv_container [Packet] Reference to the TLV
  #   group to pull the values from.
  #
  # @return [Array[Hash]] Collection of values from
  #   the single ADSI query result row.
  #
  def extract_values(tlv_container)
    values = []
    tlv_container.get_tlvs(TLV_TYPE_ANY).each do |v|
      values << extract_value(v)
    end
    values
  end

  #
  # Convert a single ADSI result value into a usable
  #   value that also describes its type.
  #
  # @param v [TLV] The TLV item that contains the value.
  #
  # @return [Hash] The type/value pair from the TLV.
  #
  def extract_value(v)
    value = {
      :type => :unknown
    }

    case v.type
    when TLV_TYPE_EXT_ADSI_STRING
      value = {
        :type  => :string,
        :value => v.value
      }
    when TLV_TYPE_EXT_ADSI_NUMBER, TLV_TYPE_EXT_ADSI_BIGNUMBER
      value = {
        :type  => :number,
        :value => v.value
      }
    when TLV_TYPE_EXT_ADSI_BOOL
      value = {
        :type  => :bool,
        :value => v.value
      }
    when TLV_TYPE_EXT_ADSI_RAW
      value = {
        :type  => :raw,
        :value => v.value
      }
    when TLV_TYPE_EXT_ADSI_ARRAY
      value = {
        :type  => :array,
        :value => extract_values(v.value)
      }
    when TLV_TYPE_EXT_ADSI_PATH
      value = {
        :type     => :path,
        :volume   => v.get_tlv_value(TLV_TYPE_EXT_ADSI_PATH_VOL),
        :path     => v.get_tlv_value(TLV_TYPE_EXT_ADSI_PATH_PATH),
        :vol_type => v.get_tlv_value(TLV_TYPE_EXT_ADSI_PATH_TYPE)
      }
    when TLV_TYPE_EXT_ADSI_DN
      values = v.get_tlvs(TLV_TYPE_ALL)
      value = {
        :type   => :dn,
        :label  => values[0].value
      }

      if values[1].type == TLV_TYPE_EXT_ADSI_STRING
        value[:string] = value[1].value
      else
        value[:raw] = value[1].value
      end
    end

    value
  end
end

end; end; end; end; end; end

