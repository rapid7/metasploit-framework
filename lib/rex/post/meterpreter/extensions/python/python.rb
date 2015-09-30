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

  def reset
    request = Packet.create_request('python_reset')
    client.send_request(request)

    return true
  end

  #
  # Dump the LSA secrets from the target machine.
  #
  # @return [Hash<Symbol,Object>]
  def execute_string(code, result_var)
    request = Packet.create_request('python_execute_string')
    request.add_tlv(TLV_TYPE_PYTHON_CODE, code)
    request.add_tlv(TLV_TYPE_PYTHON_RESULT_VAR, result_var) if result_var

    response = client.send_request(request)

    result = {
      result: response.get_tlv_value(TLV_TYPE_PYTHON_RESULT),
      stdout: "",
      stderr: ""
    }

    response.each(TLV_TYPE_PYTHON_STDOUT) do |o|
      result[:stdout] << o.value
    end

    response.each(TLV_TYPE_PYTHON_STDERR) do |e|
      result[:stderr] << e.value
    end

    result
  end

end

end; end; end; end; end

