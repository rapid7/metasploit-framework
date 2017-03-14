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

  PY_CODE_TYPE_STRING = 0
  PY_CODE_TYPE_PY     = 1
  PY_CODE_TYPE_PYC    = 2

  PY_CODE_FILE_TYPES = [ '.py', '.pyc' ]

  PY_CODE_FILE_TYPE_MAP = {
    '.py'  => PY_CODE_TYPE_PY,
    '.pyc' => PY_CODE_TYPE_PYC
  }

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

  def import(file, mod_name, result_var)
    unless ::File.file?(file)
      raise ArgumentError, "File not found: #{file}"
    end

    ext = ::File.extname(file).downcase
    unless PY_CODE_FILE_TYPES.include?(ext)
      raise ArgumentError, "File not a valid type: #{file}"
    end

    code = ::File.read(file)

    request = Packet.create_request('python_execute')
    request.add_tlv(TLV_TYPE_PYTHON_CODE, code)
    request.add_tlv(TLV_TYPE_PYTHON_CODE_LEN, code.length)
    request.add_tlv(TLV_TYPE_PYTHON_CODE_TYPE, PY_CODE_FILE_TYPE_MAP[ext])
    request.add_tlv(TLV_TYPE_PYTHON_NAME, mod_name) if mod_name
    request.add_tlv(TLV_TYPE_PYTHON_RESULT_VAR, result_var) if result_var

    run_exec_request(request)
  end

  #
  # Dump the LSA secrets from the target machine.
  #
  # @return [Hash<Symbol,Object>]
  def execute_string(code, result_var)
    request = Packet.create_request('python_execute')
    request.add_tlv(TLV_TYPE_PYTHON_CODE, code)
    request.add_tlv(TLV_TYPE_PYTHON_CODE_TYPE, PY_CODE_TYPE_STRING)
    request.add_tlv(TLV_TYPE_PYTHON_RESULT_VAR, result_var) if result_var

    run_exec_request(request)
  end

private

  def run_exec_request(request)
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

