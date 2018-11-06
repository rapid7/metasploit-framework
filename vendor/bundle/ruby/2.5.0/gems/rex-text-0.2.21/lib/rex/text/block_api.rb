# -*- coding: binary -*-
module Rex
  module Text
    # We are re-opening the module to add these module methods.
    # Breaking them up this way allows us to maintain a little higher
    # degree of organisation and make it easier to find what you're looking for
    # without hanging the underlying calls that we historically rely upon.

    #
    # Calculate the block API hash for the given module/function
    #
    # @param mod [String] The name of the module containing the target function.
    # @param fun [String] The name of the function.
    #
    # @return [String] The hash of the mod/fun pair in string format
    def self.block_api_hash(mod, func)
      unicode_mod = (mod.upcase + "\x00").unpack('C*').pack('v*')
      mod_hash = self.ror13_hash(unicode_mod)
      fun_hash = self.ror13_hash(func + "\x00")
      "0x#{(mod_hash + fun_hash & 0xFFFFFFFF).to_s(16)}"
    end

    #
    # Calculate the ROR13 hash of a given string
    #
    # @return [Integer]
    def self.ror13_hash(name)
      hash = 0
      name.unpack("C*").each {|c| hash = ror(hash, 13); hash += c }
      hash
    end
  end
end
