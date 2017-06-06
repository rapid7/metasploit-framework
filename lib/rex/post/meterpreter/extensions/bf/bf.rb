# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/bf/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module BF

###
#
# This meterpreter extensions a privilege escalation interface that is capable
# of doing things like dumping password hashes and performing local
# exploitation.
#
###
class BF < Extension


  def initialize(client)
    super(client, 'bf')

    client.register_extension_aliases(
      [
        {
          'name' => 'bf',
          'ext'  => self
        },
      ])
  end


  def execute_string(opts={})
    return nil unless opts[:code]

    request = Packet.create_request('bf_execute')
    request.add_tlv(TLV_TYPE_BF_CODE, opts[:code])

    response = client.send_request(request)
    return response.get_tlv_value(TLV_TYPE_BF_RESULT)
  end

end

end; end; end; end; end
