# -*- coding: binary -*-
require 'msf/core'

###
#
# A target for an exploit.
#
###
class Msf::Module::Target

  ###
  #
  # Target-specific brute force information, such as the addresses
  # to step, the step size (if the framework default is bad), and
  # other stuff.
  #
  ###
  class Bruteforce < Hash

    #
    # Initializes a brute force target from the supplied brute forcing
    # information.
    #
    def initialize(hash)
      update(hash)
    end

    #
    # Returns a hash of addresses that should be stepped during
    # exploitation and passed in to the bruteforce exploit
    # routine.
    #
    def start_addresses
      if (self['Start'] and self['Start'].kind_of?(Hash) == false)
        return {'Address' => self['Start'] }
      else
        return self['Start']
      end
    end

    #
    # Returns a hash of addresses that should be stopped at once
    # they are reached.
    #
    def stop_addresses
      if (self['Stop'] and self['Stop'].kind_of?(Hash) == false)
        return {'Address' => self['Stop'] }
      else
        return self['Stop']
      end
    end

    #
    # The step size to use, or zero if the framework should figure
    # it out.
    #
    def step_size
      self['Step'] || 0
    end

    #
    # Returns the default step direction.  -1 indicates that brute forcing
    # should go toward lower addresses.  1 indicates that brute forcing
    # should go toward higher addresses.
    #
    def default_direction
      dd = self['DefaultDirection']

      if (dd and dd.to_s.match(/(-1|backward)/i))
        return -1
      end

      return 1
    end

    #
    # The delay to add between attempts
    #
    def delay
      self['Delay'].to_i || 0
    end
  end

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
  def initialize(name, opts)
    opts = {} if (!opts)

    self.name           = name
    self.platform       = opts['Platform'] ? Msf::Module::PlatformList.transform(opts['Platform']) : nil
    self.save_registers = opts['SaveRegisters']
    self.ret            = opts['Ret']
    self.opts           = opts

    if (opts['Arch'])
      self.arch = Rex::Transformer.transform(opts['Arch'], Array,
        [ String ], 'Arch')
    end

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

  ##
  #
  # Target-specific payload modifications
  #
  ##

  #
  # The bad characters specific to this target for the payload.
  #
  def payload_badchars
    opts['Payload'] ? opts['Payload']['BadChars'] : nil
  end

  #
  # Payload prepend information for this target.
  #
  def payload_prepend
    opts['Payload'] ? opts['Payload']['Prepend'] : nil
  end

  #
  # Payload append information for this target.
  #
  def payload_append
    opts['Payload'] ? opts['Payload']['Append'] : nil
  end

  #
  # Payload prepend encoder information for this target.
  #
  def payload_prepend_encoder
    opts['Payload'] ? opts['Payload']['PrependEncoder'] : nil
  end

  #
  # Payload stack adjustment information for this target.
  #
  def payload_stack_adjustment
    opts['Payload'] ? opts['Payload']['StackAdjustment'] : nil
  end

  #
  # Payload max nops information for this target.
  #
  def payload_max_nops
    opts['Payload'] ? opts['Payload']['MaxNops'] : nil
  end

  #
  # Payload min nops information for this target.
  #
  def payload_min_nops
    opts['Payload'] ? opts['Payload']['MinNops'] : nil
  end

  #
  # Payload space information for this target.
  #
  def payload_space
    opts['Payload'] ? opts['Payload']['Space'] : nil
  end

  #
  # The payload encoder type or types that can be used when generating the
  # encoded payload (such as alphanum, unicode, xor, and so on).
  #
  def payload_encoder_type
    opts['Payload'] ? opts['Payload']['EncoderType'] : nil
  end

  #
  # A hash of options that be initialized in the select encoder's datastore
  # that may be required as parameters for the encoding operation.  This is
  # particularly useful when a specific encoder type is being used (as
  # specified by the EncoderType hash element).
  #
  def payload_encoder_options
    opts['Payload'] ? opts['Payload']['EncoderOptions'] : nil
  end

  #
  # Returns a hash of extended options that are applicable to payloads used
  # against this particular target.
  #
  def payload_extended_options
    opts['Payload'] ? opts['Payload']['ExtendedOptions'] : nil
  end

  #
  # The name of the target (E.g. Windows XP SP0/SP1)
  #
  attr_reader :name
  #
  # The platforms that this target is for.
  #
  attr_reader :platform
  #
  # The architectures, if any, that the target is specific to.
  #
  attr_reader :arch
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

  attr_writer :name, :platform, :arch, :opts, :ret, :save_registers # :nodoc:
  attr_writer :bruteforce # :nodoc:

end
