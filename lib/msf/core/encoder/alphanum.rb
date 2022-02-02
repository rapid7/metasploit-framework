# -*- coding: binary -*-


module Msf
  ###
  #
  # This class provides common options for certain alphanumeric encoders.
  #
  ###
  class Encoder::Alphanum < Msf::Encoder

    def initialize(info)
      super(info)

      register_options(
        [
          OptString.new('BufferRegister', [ false, 'The register that points to the encoded payload' ]),
          OptInt.new('BufferOffset', [ false, 'The offset to the buffer from the start of the register', 0 ]),
          OptBool.new('AllowWin32SEH', [ true, 'Use SEH to determine the address of the stub (Windows only)', false ])
        ], Msf::Encoder::Alphanum
      )
    end

  end
end
