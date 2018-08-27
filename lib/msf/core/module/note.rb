# -*- coding: binary -*-
require 'msf/core'

###
#
# A note containing extra information pertaining to the module.
#
###
class Msf::Module::Notes

  def initialize(opts)
    opts = {} unless opts

    if opts['AKA']
      self.aka = Msf::Module::Aka.new(opts['AKA'])
    end

    if opts['NOCVE']
      self.nocve = Msf::Module::NoCve.new(opts['NOCVE'])
    end

  end

  def self.transform(src)
    Rex::Transformer.transform(src, Array, [ Hash ], 'Notes')
  end

  #
  # Alias names (also-known-as) for the module
  #
  attr_reader :aka

  #
  # A description explaining why a module lacks a CVE, if applicable
  #
  attr_reader :nocve

protected

  attr_writer :aka, :nocve

end


class Msf::Module::GenericNote

  def initialize(type, value)
    @type = type
    @value = value
  end

  attr_reader :type, :value

end


class Msf::Module::Aka < Msf::Module::GenericNote

  def initialize(value)
    super('AKA', value)
  end

end


class Msf::Module::NoCve < Msf::Module::GenericNote

  def initialize(value)
    super('NOCVE', value)
  end

end
