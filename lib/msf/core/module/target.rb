# -*- coding: binary -*-
require 'msf/core'

###
#
# A target for an exploit.
#
###
class Msf::Module::Target
  require 'msf/core/module/target/bruteforce'

  require 'msf/core/module/target/architectures'
  include Msf::Module::Target::Architectures

  require 'msf/core/module/target/payload'
  include Msf::Module::Target::Payload

  require 'msf/core/module/target/platforms'
  include Msf::Module::Target::Platforms

  #
  # Attributes
  #

  # @!attribute metasploit_instance
  #   Metasploit instance on which these targets
  #
  #   @return [Msf::Exploit]
  attr_accessor :metasploit_instance

  #
  # Methods
  #

  #
  # Serialize from an array to a Target instance.
  #
  def self.from_a(ary)
    return nil if (ary.length < 2)

    self.new(ary.shift, ary.shift)
  end

  #
  # Transforms the supplied source into an array of Targets.
  #
  def self.transform(src)
    Rex::Transformer.transform(src, Array, [ self, String ], 'Target')
  end

  #
  # Initializes an instance of a bruteforce target from the supplied
  # information.  The hash of options that this constructor takes is as
  # follows:
  #
  # Platform
  #
  # 	The platform(s) that this target is to operate against.
  #
  # SaveRegisters
  #
  # 	The registers that must be saved by NOP generators.
  #
  # Arch
  #
  # 	The architectures, if any, that this target is specific to (E.g.
  # 	ARCH_X86).
  #
  # Bruteforce
  #
  # 	Settings specific to a target that supports brute forcing.  See the
  # 	BruteForce class.
  #
  # Ret
  #
  # 	The target-specific return address or addresses that will be used.
  #
  # Payload
  #
  # 	Payload-specific options, such as append, prepend, and other values that
  # 	can be set on a per-exploit or per-target basis.
  #
  def initialize(name, opts={})
    opts ||= {}

    self.name           = name
    self.save_registers = opts['SaveRegisters']
    self.ret            = opts['Ret']
    self.opts           = opts

    # Does this target have brute force information?
    if (opts['Bruteforce'])
      self.bruteforce = Bruteforce.new(opts['Bruteforce'])
    end
  end

  #
  # Index the options directly.
  #
  def [](key)
    opts[key]
  end

  #
  # Returns whether or not this is a bruteforce target, forces boolean
  # result.
  #
  def bruteforce?
    return (bruteforce != nil)
  end

  #
  # The name of the target (E.g. Windows XP SP0/SP1)
  #
  attr_reader :name
  #
  # The target-specific options, like payload settings and other stuff like
  # that.
  #
  attr_reader :opts
  #
  # An alias for the target 'Ret' option.
  #
  attr_reader :ret
  #
  # The list of registers that need to be saved.
  #
  attr_reader :save_registers
  #
  # The bruteforce target information that will be non-nil if a Bruteforce
  # option is passed to the constructor of the class.
  #
  attr_reader :bruteforce

protected

  attr_writer :name, :platform, :opts, :ret, :save_registers # :nodoc:
  attr_writer :bruteforce # :nodoc:

end
