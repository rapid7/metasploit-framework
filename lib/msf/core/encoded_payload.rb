# -*- coding: binary -*-

require 'msf/core'

module Msf

###
#
# This class wrappers an encoded payload buffer and the means used to create
# one.
#
###
class EncodedPayload

  include Framework::Offspring

  #
  # This method creates an encoded payload instance and returns it to the
  # caller.
  #
  def self.create(pinst, reqs = {})
    # Create the encoded payload instance
    p = EncodedPayload.new(pinst.framework, pinst, reqs)

    p.generate(reqs['Raw'])

    return p
  end

  #
  # Creates an instance of an EncodedPayload.
  #
  def initialize(framework, pinst, reqs)
    self.framework = framework
    self.pinst     = pinst
    self.reqs      = reqs
  end

  #
  # This method generates the full encoded payload and returns the encoded
  # payload buffer.
  #
  # @return [String] The encoded payload.
  def generate(raw = nil)
    self.raw           = raw
    self.encoded       = nil
    self.nop_sled_size = 0
    self.nop_sled      = nil
    self.encoder       = nil
    self.nop           = nil
    self.iterations    = reqs['Iterations'].to_i
    self.iterations    = 1 if self.iterations < 1

    # Increase thread priority as necessary.  This is done
    # to ensure that the encoding and sled generation get
    # enough time slices from the ruby thread scheduler.
    priority = Thread.current.priority

    if (priority == 0)
      Thread.current.priority = 1
    end

    begin
      # First, validate
      pinst.validate()

      # Generate the raw version of the payload first
      generate_raw() if self.raw.nil?

      # Encode the payload
      encode()

      # Build the NOP sled
      generate_sled()

      # Finally, set the complete payload definition
      self.encoded = (self.nop_sled || '') + self.encoded
    ensure
      # Restore the thread priority
      Thread.current.priority = priority
    end

    # Return the complete payload
    return encoded
  end

  #
  # Generates the raw payload from the payload instance.  This populates the
  # {#raw} attribute.
  #
  # @return [String] The raw, unencoded payload.
  def generate_raw
    self.raw = (reqs['Prepend'] || '') + pinst.generate + (reqs['Append'] || '')

    # If an encapsulation routine was supplied, then we should call it so
    # that we can get the real raw payload.
    if reqs['EncapsulationRoutine']
      self.raw = reqs['EncapsulationRoutine'].call(reqs, raw)
    end
  end

  #
  # Scans for a compatible encoder using ranked precedence and populates the
  # encoded attribute.
  #
  def encode
    # If the exploit has bad characters, we need to run the list of encoders
    # in ranked precedence and try to encode without them.
    if reqs['BadChars'] or reqs['Encoder'] or reqs['ForceEncode']
      encoders = pinst.compatible_encoders

      # Fix encoding issue
      if reqs['Encoder']
        reqs['Encoder'] = reqs['Encoder'].encode(framework.encoders.keys[0].encoding)
      end
      # If the caller had a preferred encoder, use this encoder only
      if ((reqs['Encoder']) and (preferred = framework.encoders[reqs['Encoder']]))
        encoders = [ [reqs['Encoder'], preferred] ]
      elsif (reqs['Encoder'])
        wlog("#{pinst.refname}: Failed to find preferred encoder #{reqs['Encoder']}")
        raise NoEncodersSucceededError, "Failed to find preferred encoder #{reqs['Encoder']}"
      end

      encoders.each { |encname, encmod|
        self.encoder = encmod.new
        self.encoded = nil

        # If there is an encoder type restriction, check to see if this
        # encoder matches with what we're searching for.
        if ((reqs['EncoderType']) and
            (self.encoder.encoder_type.split(/\s+/).include?(reqs['EncoderType']) == false))
          wlog("#{pinst.refname}: Encoder #{encoder.refname} is not a compatible encoder type: #{reqs['EncoderType']} != #{self.encoder.encoder_type}",
            'core', LEV_1)
          next
        end

        # If the exploit did not explicitly request a kind of encoder and
        # the current encoder has a manual ranking, then it should not be
        # considered as a valid encoder.  A manual ranking tells the
        # framework that an encoder must be explicitly defined as the
        # encoder of choice for an exploit.
        if ((reqs['EncoderType'].nil?) and
            (reqs['Encoder'].nil?) and
            (self.encoder.rank == ManualRanking))
          wlog("#{pinst.refname}: Encoder #{encoder.refname} is manual ranked and was not defined as a preferred encoder.",
            'core', LEV_1)
          next
        end

        # Import the datastore from payload (and likely exploit by proxy)
        self.encoder.share_datastore(pinst.datastore)

        # If we have any encoder options, import them into the datastore
        # of the encoder.
        if (reqs['EncoderOptions'])
          self.encoder.datastore.import_options_from_hash(reqs['EncoderOptions'])
        end

        # Validate the encoder to make sure it's properly initialized.
        begin
          self.encoder.validate
        rescue ::Exception
          wlog("#{pinst.refname}: Failed to validate encoder #{encoder.refname}: #{$!}",
            'core', LEV_1)
          next
        end

        eout = self.raw.dup

        next_encoder = false

        # Try encoding with the current encoder
        #
        # NOTE: Using more than one iteration may cause successive iterations to switch
        # to using a different encoder.
        #
        1.upto(self.iterations) do |iter|
          err_start = "#{pinst.refname}: iteration #{iter}"

          begin
            eout = self.encoder.encode(eout, reqs['BadChars'], nil, pinst.platform)
          rescue EncodingError
            wlog("#{err_start}: Encoder #{encoder.refname} failed: #{$!}", 'core', LEV_1)
            dlog("#{err_start}: Call stack\n#{$@.join("\n")}", 'core', LEV_3)
            next_encoder = true
            break

          rescue ::Exception
            elog("#{err_start}: Broken encoder #{encoder.refname}: #{$!}", 'core', LEV_0)
            dlog("#{err_start}: Call stack\n#{$@.join("\n")}", 'core', LEV_1)
            next_encoder = true
            break
          end

          # Get the minimum number of nops to use
          min = (reqs['MinNops'] || 0).to_i
          min = 0 if reqs['DisableNops']

          # Check to see if we have enough room for the minimum requirements
          if ((reqs['Space']) and (reqs['Space'] < eout.length + min))
            wlog("#{err_start}: Encoded payload version is too large with encoder #{encoder.refname}",
              'core', LEV_1)
            next_encoder = true
            break
          end

          ilog("#{err_start}: Successfully encoded with encoder #{encoder.refname} (size is #{eout.length})",
            'core', LEV_0)
        end

        next if next_encoder

        self.encoded = eout
        break
      }

      # If the encoded payload is nil, raise an exception saying that we
      # suck at life.
      if (self.encoded == nil)
        self.encoder = nil

        raise NoEncodersSucceededError,
          "#{pinst.refname}: All encoders failed to encode.",
          caller
      end

    # If there are no bad characters, then the raw is the same as the
    # encoded
    else
      self.encoded = raw
    end

    # Prefix the prepend encoder value
    self.encoded = (reqs['PrependEncoder'] || '') + self.encoded
  end

  #
  # Construct a NOP sled if necessary
  #
  def generate_sled
    min   = reqs['MinNops'] || 0
    space = reqs['Space']

    self.nop_sled_size = min

    # Calculate the number of NOPs to pad out the buffer with based on the
    # requirements.  If there was a space requirement, check to see if
    # there's any room at all left for a sled.
    if ((space) and
       (space > encoded.length))
      self.nop_sled_size = reqs['Space'] - self.encoded.length
    end

    # If the maximum number of NOPs has been exceeded, wrap it back down.
    if ((reqs['MaxNops']) and
       (reqs['MaxNops'] < self.nop_sled_size))
      self.nop_sled_size = reqs['MaxNops']
    end

    # Check for the DisableNops setting
    self.nop_sled_size = 0 if reqs['DisableNops']

    # Now construct the actual sled
    if (self.nop_sled_size > 0)
      nops = pinst.compatible_nops

      # If the caller had a preferred nop, try to find it and prefix it
      if ((reqs['Nop']) and
          (preferred = framework.nops[reqs['Nop']]))
        nops.unshift([reqs['Nop'], preferred ])
      elsif (reqs['Nop'])
        wlog("#{pinst.refname}: Failed to find preferred nop #{reqs['Nop']}")
      end

      nops.each { |nopname, nopmod|
        # Create an instance of the nop module
        self.nop = nopmod.new

        # Propagate options from the payload and possibly exploit
        self.nop.share_datastore(pinst.datastore)

        # The list of save registers
        save_regs = (reqs['SaveRegisters'] || []) + (pinst.save_registers || [])

        if (save_regs.empty? == true)
          save_regs = nil
        end

        begin
          nop.copy_ui(pinst)

          self.nop_sled = nop.generate_sled(self.nop_sled_size,
            'BadChars'      => reqs['BadChars'],
            'SaveRegisters' => save_regs)
        rescue
          dlog("#{pinst.refname}: Nop generator #{nop.refname} failed to generate sled for payload: #{$!}",
            'core', LEV_1)

          self.nop = nil
        end

        break
      }

      if (self.nop_sled == nil)
        raise NoNopsSucceededError,
          "#{pinst.refname}: All NOP generators failed to construct sled for.",
          caller
      end
    else
      self.nop_sled = ''
    end

    return self.nop_sled
  end


  #
  # Convert the payload to an executable appropriate for its arch and
  # platform.
  #
  # +opts+ are passed directly to +Msf::Util::EXE.to_executable+
  #
  # see +Msf::Exploit::EXE+
  #
  def encoded_exe(opts={})
    # Ensure arch and platform are in the format that to_executable expects
    if opts[:arch] and not opts[:arch].kind_of? Array
      opts[:arch] = [ opts[:arch] ]
    end
    if (opts[:platform].kind_of? Msf::Module::PlatformList)
      opts[:platform] = opts[:platform].platforms
    end

    emod = pinst.assoc_exploit if pinst.respond_to? :assoc_exploit

    if emod
      if (emod.datastore["EXE::Custom"] and emod.respond_to? :get_custom_exe)
        return emod.get_custom_exe
      end
      # This is a little ghetto, grabbing datastore options from the
      # associated exploit, but it doesn't really make sense for the
      # payload to have exe options if the exploit doesn't need an exe.
      # Msf::Util::EXE chooses reasonable defaults if these aren't given,
      # so it's not that big of an issue.
      opts.merge!({
        :template_path => emod.datastore['EXE::Path'],
        :template => emod.datastore['EXE::Template'],
        :inject => emod.datastore['EXE::Inject'],
        :fallback => emod.datastore['EXE::FallBack'],
        :sub_method => emod.datastore['EXE::OldMethod']
      })
      # Prefer the target's platform/architecture information, but use
      # the exploit module's if no target specific information exists.
      opts[:platform] ||= emod.target_platform  if emod.respond_to? :target_platform
      opts[:platform] ||= emod.platform         if emod.respond_to? :platform
      opts[:arch] ||= emod.target_arch          if emod.respond_to? :target_arch
      opts[:arch] ||= emod.arch                 if emod.respond_to? :arch
    end
    # Lastly, try the payload's. This always happens if we don't have an
    # associated exploit module.
    opts[:platform] ||= pinst.platform if pinst.respond_to? :platform
    opts[:arch] ||= pinst.arch         if pinst.respond_to? :arch

    Msf::Util::EXE.to_executable(framework, opts[:arch], opts[:platform], encoded, opts)
  end

  #
  # Generate a jar file containing the encoded payload.
  #
  # Uses the payload's +generate_jar+ method if it is implemented (Java
  # payloads should all have it).  Otherwise, converts the payload to an
  # executable and uses Msf::Util::EXE.to_jar to create a jar file that dumps
  # the exe out to a random file name in the system's temporary directory and
  # executes it.
  #
  def encoded_jar(opts={})
    return pinst.generate_jar(opts) if pinst.respond_to? :generate_jar

    opts[:spawn] ||= pinst.datastore["Spawn"]

    Msf::Util::EXE.to_jar(encoded_exe(opts), opts)
  end

  #
  # Similar to +encoded_jar+ but builds a web archive for use in servlet
  # containers such as Tomcat.
  #
  def encoded_war(opts={})
    return pinst.generate_war(opts) if pinst.respond_to? :generate_war

    Msf::Util::EXE.to_jsp_war(encoded_exe(opts), opts)
  end

  #
  # The raw version of the payload
  #
  attr_reader :raw
  #
  # The encoded version of the raw payload plus the NOP sled
  # if one was generated.
  #
  attr_reader :encoded
  #
  # The size of the NOP sled
  #
  attr_reader :nop_sled_size
  #
  # The NOP sled itself
  #
  attr_reader :nop_sled
  #
  # The encoder that was used
  #
  attr_reader :encoder
  #
  # The NOP generator that was used
  #
  attr_reader :nop
  #
  # The number of encoding iterations used
  #
  attr_reader :iterations

protected

  attr_writer :raw # :nodoc:
  attr_writer :encoded # :nodoc:
  attr_writer :nop_sled_size # :nodoc:
  attr_writer :nop_sled # :nodoc:
  attr_writer :payload # :nodoc:
  attr_writer :encoder # :nodoc:
  attr_writer :nop # :nodoc:
  attr_writer :iterations # :nodoc:

  #
  # The payload instance used to generate the payload
  #
  attr_accessor :pinst
  #
  # The requirements used for generation
  #
  attr_accessor :reqs

end

end
