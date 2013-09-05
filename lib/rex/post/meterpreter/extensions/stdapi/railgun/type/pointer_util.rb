# -*- coding: binary -*-
require 'rex/post/meterpreter/extensions/stdapi/railgun/platform_util'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Type
module PointerUtil

  ARCH_POINTER_SIZE = {
    PlatformUtil::X86_64 => 8,
    PlatformUtil::X86_32 => 4
  }.freeze

  # Returns the pointer size for this architecture. Should accept client or platform or arch
  def self.pointer_size(platform)
    ARCH_POINTER_SIZE[platform]
  end

  def self.pack_pointer(pointer, platform)
    if pointer.nil?
      return pack_pointer(0, platform)
    end

    case platform
    when PlatformUtil::X86_64
      # XXX: Only works if attacker and victim are like-endianed
      [pointer].pack('Q')
    when PlatformUtil::X86_32
      [pointer].pack('V')
    else
      raise "platform symbol #{platform.to_s} not supported"
    end
  end

  # Given a packed pointer, unpack it according to architecture
  def self.unpack_pointer(packed_pointer, platform)
    case platform
    when PlatformUtil::X86_64
      # XXX: Only works if attacker and victim are like-endianed
      packed_pointer.unpack('Q').first
    when PlatformUtil::X86_32
      packed_pointer.unpack('V').first
    else
      raise "platform symbol #{platform.to_s} not supported"
    end
  end

  def self.null_pointer(pointer, platform)
    pack_pointer(0, platform)
  end

  ###
  # Summary: Returns true if pointer will be considered a 'null' pointer
  #
  # If given nil, returns true
  # If given 0, returns true
  # If given a string, if 0 after unpacking, returns true
  # false otherwise
  ##
  def self.is_null_pointer?(pointer, platform)
    if pointer.kind_of?(String)
      pointer = unpack_pointer(pointer, platform)
    end

    return pointer.nil? || pointer == 0
  end
#
#	def self.is_unpacked_pointer?(pointer, platform)
#		# TODO also check that the integer size is appropriate for the platform
#		unless pointer.kind_of?(Fixnum) and pointer > 0 # and pointer <
#			return false
#		end
#
#		packed_pointer = pack_pointer(pointer, platform)
#		if !packed_pointer.nil? and packed_pointer.length == pointer_size(platform)
#			return true
#		end
#
#		return false
#	end
#
  # Returns true if the data type is a pointer, false otherwise
  def self.is_pointer_type?(type)
    if type == :pointer
      return true
    end

    if type.kind_of?(String) && type =~ /^L?P/
      return true
    end

    return false
  end

end # PointerUtil
end # Type
end # Railgun
end # Stdapi
end # Extensions
end # Meterpreter
end # Post
end # Rex
