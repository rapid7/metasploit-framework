# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/powershell/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Powershell

###
#
# This meterpreter extensions a privilege escalation interface that is capable
# of doing things like dumping password hashes and performing local
# exploitation.
#
###
class Powershell < Extension


  def initialize(client)
    super(client, 'powershell')

    client.register_extension_aliases(
      [
        {
          'name' => 'powershell',
          'ext'  => self
        },
      ])
  end


  def execute_string(code)
    request = Packet.create_request('powershell_execute')
    request.add_tlv(TLV_TYPE_POWERSHELL_CODE, code)

    response = client.send_request(request)
    return response.get_tlv_value(TLV_TYPE_POWERSHELL_RESULT)
  end

end

end; end; end; end; end
