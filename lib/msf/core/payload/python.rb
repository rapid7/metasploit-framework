# -*- coding: binary -*-
require 'msf/core'

module Msf::Payload::Python

  def initialize(info = {})
    super(merge_info(info,
      'Arch'        => ARCH_PYTHON,
      'RequiredCmd' => 'python'))
  end

  # convert python code to one line
  def flatten(python_code)
    # Base64 encoding is required in order to handle Python's formatting
    # requirements in the while loop.
    b64data = Rex::Text.encode_base64(python_code)
    return "import base64; exec(base64.b64decode('#{b64data}'))"
  end

  def to_command(payload)
    if payload !~ /^import base64; exec\(base64.b64decode\('[a-zA-Z0-9+]+={0,2}'\)\)$/
      payload = flatten(payload)
    end
    return "python -c \"#{payload}\""
  end

end
