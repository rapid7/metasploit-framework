# -*- coding: binary -*-
require 'msf/core'

module Msf

###
#
# This class provides common options for certain alphanumeric encoders.
#
###
class Encoder::NonUpper < Msf::Encoder

  def initialize(info)
    super(info)
  end

end

end
