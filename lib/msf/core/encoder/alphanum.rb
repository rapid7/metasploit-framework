# -*- coding: binary -*-
require 'msf/core'

module Msf

###
#
# This class provides common options for certain alphanumeric encoders.
#
###
class Encoder::Alphanum < Msf::Encoder

  def initialize(info)
    super(info)

    off = 0

    register_options(
      [
        OptString.new('BufferRegister', [ false, "The register that pointers to the encoded payload" ]),
        OptInt.new('BufferOffset', [ false, "The offset to the buffer from the start of the register", off ]),
        OptBool.new('AllowWin32SEH', [ true, "Use SEH to determine the address of the stub (Windows only)", false ])
      ], Msf::Encoder::Alphanum)
  end

end

end

