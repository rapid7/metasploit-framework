# -*- coding: binary -*-
require 'msf/core'

module Msf::Payload::R

  def initialize(info = {})
    super(info)
  end

  def prepends(buf)
    buf
  end

end
