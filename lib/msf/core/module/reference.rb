# -*- coding: binary -*-
require 'msf/core'

###
#
# A reference to some sort of information.  This is typically a URL, but could
# be any type of referential value that people could use to research a topic.
#
###
class Msf::Module::Reference

  #
  # Serialize a reference from a string.
  #
  def self.from_s(str)
    return self.new(str)
  end

  #
  # Initializes a reference from a string.
  #
  def initialize(in_str)
    self.str = in_str
  end

  #
  # Compares references to see if their equal.
  #
  def ==(tgt)
    return (tgt.to_s == to_s)
  end

  #
  # Returns the reference as a string.
  #
  def to_s
    return self.str
  end

  #
  # Serializes the reference instance from a string.
  #
  def from_s(in_str)
    self.str = in_str
  end

  #
  # The reference string.
  #
  attr_reader :str

protected

  attr_writer :str # :nodoc:

end
