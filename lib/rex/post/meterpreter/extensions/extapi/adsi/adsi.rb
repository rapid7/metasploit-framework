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

  # Enumerate all the users in the given domain.
  def user_enumerate(domain_name)
    request = Packet.create_request('extapi_adsi_user_enum')

    request.add_tlv(TLV_TYPE_EXT_ADSI_DOMAIN, domain_name)

    response = client.send_request(request)

    users = []

    response.each(TLV_TYPE_EXT_ADSI_USER) { |u|
      users << {
        :sam          => u.get_tlv_value(TLV_TYPE_EXT_ADSI_USER_SAM) || "",
        :dn           => u.get_tlv_value(TLV_TYPE_EXT_ADSI_USER_DN) || "",
        :name         => u.get_tlv_value(TLV_TYPE_EXT_ADSI_USER_NAME) || "",
        :desc         => u.get_tlv_value(TLV_TYPE_EXT_ADSI_USER_DESC) || "",
        :comment      => u.get_tlv_value(TLV_TYPE_EXT_ADSI_USER_COMMENT) || ""
      }
    }

    users.sort_by { |w| w[:sam] }
  end

  # Enumerate all the computers in the given domain.
  def computer_enumerate(domain_name)
    request = Packet.create_request('extapi_adsi_computer_enum')

    request.add_tlv(TLV_TYPE_EXT_ADSI_DOMAIN, domain_name)

    response = client.send_request(request)

    computers = []

    response.each(TLV_TYPE_EXT_ADSI_COMP) { |c|
      computers << {
        :dn      => c.get_tlv_value(TLV_TYPE_EXT_ADSI_COMP_DN) || "",
        :name    => c.get_tlv_value(TLV_TYPE_EXT_ADSI_COMP_NAME) || "",
        :desc    => c.get_tlv_value(TLV_TYPE_EXT_ADSI_COMP_DESC) || "",
        :comment => c.get_tlv_value(TLV_TYPE_EXT_ADSI_COMP_COMMENT) || ""
      }
    }

    computers.sort_by { |w| w[:name] }
  end

  attr_accessor :client

end

end; end; end; end; end; end

