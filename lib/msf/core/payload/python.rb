# -*- coding: binary -*-
require 'msf/core'

module Msf::Payload::Python

  def initialize(info = {})
    super(merge_info(info,
      'Arch'        => ARCH_PYTHON,
      'RequiredCmd' => 'python'))
  end

  def to_command(payload)
    return "python -c \"#{payload}\""
  end

end
