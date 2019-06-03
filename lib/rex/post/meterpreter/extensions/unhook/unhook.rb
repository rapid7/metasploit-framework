# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/unhook/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Unhook

###
#
# This meterpreter extension can be used to unhook PSP products
#
###
#
class Unhook < Extension
  UNHOOK_ERROR_SUCCESS = 0

  def initialize(client)
    super(client, 'unhook')

    client.register_extension_aliases(
      [
        {
          'name' => 'unhook',
          'ext'  => self
        },
      ])
  end

  def unhook_pe
    request = Packet.create_request('unhook_pe')
    response = client.send_request(request)
    response_code = response.get_tlv_value(TLV_TYPE_UNHOOK_ERROR_CODE)

    raise Exception, "Did not get ERROR_SUCCESS back!" if response_code != UNHOOK_ERROR_SUCCESS
    return 0, response_code, nil
  end

end
end; end; end; end; end
