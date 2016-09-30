# -*- coding: binary -*-
require 'msf/core'

###
#
# A target for an exploit.
#
###
class Msf::Module::AuxiliaryAction


  #
  # Serialize from an array to an Action instance.
  #
  def self.from_a(ary)
    return nil if ary.nil?
    self.new(*ary)
  end

  #
  # Transforms the supplied source into an array of AuxiliaryActions.
  #
  def self.transform(src)
    Rex::Transformer.transform(src, Array, [ self, String ], 'AuxiliaryAction')
  end

  #
  # Creates a new action definition
  #
  def initialize(name, opts={})
    self.name        = name
    self.opts        = opts
    self.description = opts['Description'] || ''
  end

  #
  # Index the options directly.
  #
  def [](key)
    opts[key]
  end

  #
  # The name of the action ('info')
  #
  attr_reader :name
  #
  # The action's description
  #
  attr_reader :description
  #
  # Action specific parameters
  #
  attr_reader :opts

protected

  attr_writer :name, :opts, :description # :nodoc:

end
