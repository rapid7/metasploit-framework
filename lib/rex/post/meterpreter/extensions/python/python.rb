# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/python/tlv'
require 'set'

module Rex
module Post
module Meterpreter
module Extensions
module Python

###
#
# Python extension - gives remote python scripting capabilities on the target.
#
###

class Python < Extension

  #
  # Typical extension initialization routine.
  #
  # @param client (see Extension#initialize)
  def initialize(client)
    super(client, 'python')

    client.register_extension_aliases(
      [
        {
          'name' => 'python',
          'ext'  => self
        }
      ])
  end

  #
  # Dump the LSA secrets from the target machine.
  #
  # @return [Hash<Symbol,Object>]
  def execute_string(code)
    request = Packet.create_request('python_execute_string')
    request.add_tlv(TLV_TYPE_PYTHON_STRING, code)

    response = client.send_request(request)

    response.get_tlv_value(TLV_TYPE_PYTHON_OUTPUT)
  end

end

end; end; end; end; end

