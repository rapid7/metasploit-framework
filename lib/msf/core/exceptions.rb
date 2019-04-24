# -*- coding: binary -*-
require 'msf/core'

module Msf

###
#
# Mixin that should be included in all exceptions that can be raised from the
# framework so that they can be universally caught.  Framework exceptions
# automatically extended Rex exceptions
#
###
module Exception
  include Rex::Exception
end

###
#
# This exception is raised when one or more options failed
# to pass data store validation.  The list of option names
# can be obtained through the options attribute.
#
###
class OptionValidateError < ArgumentError
  include Exception

  def initialize(options = [])
    @options = options
  end

  def to_s
    "The following options failed to validate: #{options.join(', ')}."
  end

  attr_reader :options
end

###
#
# This exception is raised when something failed to validate properly.
#
###
class ValidationError < ArgumentError
  include Exception

  def to_s
    "One or more requirements could not be validated."
  end
end

###
#
# This exception is raised when the module cache is invalidated.  It is
# handled internally by the ModuleManager.
#
###
class ModuleCacheInvalidated < RuntimeError
end

##
#
# Encoding exceptions
#
##

###
#
# This exception is raised to indicate that an encoding error of some sort has
# occurred.
#
###
class EncodingError < RuntimeError
  include Exception

  def to_s
    "An encoding exception occurred."
  end
end

###
#
# Thrown when an encoder fails to find a viable encoding key.
#
###
class NoKeyError < EncodingError
  def to_s
    "A valid encoding key could not be found."
  end
end

###
#
# Thrown when an encoder fails to encode a buffer due to a bad character.
#
###
class BadcharError < EncodingError
  def initialize(buf = nil, index = nil, stub_size = nil, char = nil)
    @buf       = buf
    @index     = index
    @stub_size = stub_size
    @char      = char
  end

  def to_s
    # Deal with elements of a String being an instance of String instead of
    # Integer in ruby 1.9.
    if (char.respond_to? :ord)
      c = char.ord
    else
      c = char
    end
    if (c)
      return "Encoding failed due to a bad character (index=#{index}, char=#{sprintf("0x%.2x", c)})"
    else
      return "Encoding failed due to a nil character"
    end
  end

  attr_reader :buf, :index, :stub_size, :char
end

###
#
# This exception is raised when no encoders succeed to encode a buffer.
#
###
class NoEncodersSucceededError < EncodingError

  def to_s
    "No encoders encoded the buffer successfully."
  end
end

###
#
# Thrown when an encoder fails to generate a valid opcode sequence.
#
###
class BadGenerateError < EncodingError
  def to_s
    "A valid opcode permutation could not be found."
  end
end

##
#
# Exploit exceptions
#
##

###
#
# This exception is raised to indicate a general exploitation error.
#
###
module ExploitError
  include Exception

  def to_s
    "An exploitation error occurred."
  end
end

###
#
# This exception is raised to indicate a general auxiliary error.
#
###
module AuxiliaryError
  include Exception

  def to_s
    "An auxiliary error occurred."
  end
end

###
#
# This exception is raised if a target was not specified when attempting to
# exploit something.
#
###
class MissingTargetError < ArgumentError
  include ExploitError

  def to_s
    "A target has not been selected."
  end
end

###
#
# This exception is raised if a payload was not specified when attempting to
# exploit something.
#
###
class MissingPayloadError < ArgumentError
  include ExploitError

  def to_s
    "A payload has not been selected."
  end
end

###
#
# This exception is raised if a valid action was not specified when attempting to
# run an auxiliary module.
#
###
class MissingActionError < ArgumentError
  include AuxiliaryError
  attr_accessor :reason

  def initialize(reason='')
    self.reason = reason
    super
  end

  def to_s
    "Invalid action: #{reason}"
  end
end

###
#
# This exception is raised if an incompatible payload was specified when
# attempting to exploit something.
#
###
class IncompatiblePayloadError < ArgumentError
  include ExploitError

  def initialize(pname = nil)
    @pname = pname
  end

  def to_s
    "#{pname} is not a compatible payload."
  end

  #
  # The name of the payload that was used.
  #
  attr_reader :pname
end

class NoCompatiblePayloadError < ArgumentError
  include Exception
end

##
#
# NOP exceptions
#
##

###
#
# This exception is raised to indicate that a general NOP error occurred.
#
###
module NopError
  include Exception

  def to_s
    "A NOP generator error occurred."
  end
end

###
#
# This exception is raised when no NOP generators succeed at generating a
# sled.
#
###
class NoNopsSucceededError < RuntimeError
  include NopError

  def to_s
    "No NOP generators succeeded."
  end
end

##
#
# Plugin exceptions
#
##

class PluginLoadError < RuntimeError
  include Exception
  attr_accessor :reason

  def initialize(reason='')
    self.reason = reason
    super
  end

  def to_s
    "This plugin failed to load:  #{reason}"
  end
end

##
#
# This exception is raised if an payload option string exceeds the maximum allowed size
# during the payload generation.
#
##
  class PayloadItemSizeError < ArgumentError
    include Exception

    def initialize(item = nil, max_size = nil)
      @item = item
      @maxSize = max_size
    end

    def to_s
      "Option value: #{item.slice(0..30)} is to big (Current length: #{item.length}). Maximum length: #{maxSize}"
    end

    attr_reader :item # The content of the payload option (for example a URL)
    attr_reader :maxSize # The maximum allowed size of the payload option
  end


end
