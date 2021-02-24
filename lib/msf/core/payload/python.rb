# -*- coding: binary -*-

module Msf::Payload::Python

  #
  # Encode the given python command in base64 and wrap it with a stub
  # that will decode and execute it on the fly. The code will be condensed to
  # one line and compatible with all Python versions supported by the Python
  # Meterpreter stage.
  #
  # @param cmd [String] The python code to execute.
  # @return [String] Full python stub to execute the command.
  #
  def self.create_exec_stub(cmd)
    # Base64 encoding is required in order to handle Python's formatting
    b64_stub = "exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('#{Rex::Text.encode_base64(cmd)}')[0]))"
    b64_stub
  end
  
  def py_create_exec_stub(cmd)
    Msf::Payload::Python.create_exec_stub(cmd)
  end

end
