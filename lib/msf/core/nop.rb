# -*- coding: binary -*-
require 'msf/core'

module Msf

###
#
# This class acts as the base class for all nop generators.
#
###
class Nop < Msf::Module
  self.module_type = Metasploit::Model::Module::Type::NOP

  #
  # Initializes the NOP generator, defaulting it to being usable on all
  # platforms.
  #
  def initialize(info = {})
    super({
        'Platform' => '' # All platforms by default
      }.update(info))
  end

  #
  # Stub method for generating a sled with the provided arguments.  Derived
  # Nop implementations must supply a length and can supply one or more of
  # the following options:
  #
  #   - Random (true/false)
  #     Indicates that the caller desires random NOPs (if supported).
  #   - SaveRegisters (array)
  #     The list of registers that should not be clobbered by the NOP
  #     generator.
  #   - BadChars (string)
  #     The list of characters that should be avoided by the NOP
  #     generator.
  #
  def generate_sled(length, opts)
    return nil
  end

  #
  # Default repetition threshold when finding nop characters.
  #
  def nop_repeat_threshold
    return 10000
  end

end

end
