# -*- coding: binary -*-
require 'metasm'

module Msf

###
#
# This class represents the base class for a logical payload.  The framework
# automatically generates payload combinations at runtime which are all
# extended from this Payload as a base class.
#
###
class Payload < Msf::Module


  # Platform specific includes
  require 'metasploit/framework/compiler/mingw'

  # Universal payload includes

  ##
  #
  # Payload types
  #
  ##
  module Type
    #
    # Single payload type.  These types of payloads are self contained and
    # do not go through any staging.
    #
    Single = (1 << 0)

    #
    # The stager half of a staged payload.  Its responsibility in life is to
    # read in the stage and execute it.
    #
    Stager = (1 << 1)

    #
    # The stage half of a staged payload.  This payload performs whatever
    # arbitrary task it's designed to do, possibly making use of the same
    # connection that the stager used to read the stage in on, if
    # applicable.
    #
    Stage  = (1 << 2)

    Adapter = (1 << 3)
  end

  #
  # Creates an instance of a payload module using the supplied information.
  #
  def initialize(info = {})
    super

    #
    # Gets the Dependencies if the payload requires external help
    # to work
    #
    self.module_info['Dependencies'] = self.module_info['Dependencies'] || []

    # If this is an adapted or staged payload but there is no stage information,
    # then this is actually a stager + single combination.  Set up the
    # information hash accordingly.
    if (self.class.include?(Msf::Payload::Adapter) || self.class.include?(Msf::Payload::Single)) and self.class.include?(Msf::Payload::Stager)

      if self.module_info['Payload']
        self.module_info['Stage']['Payload']  = self.module_info['Payload']['Payload'] || ""
        self.module_info['Stage']['Assembly'] = self.module_info['Payload']['Assembly'] || ""
        self.module_info['Stage']['Offsets']  = self.module_info['Payload']['Offsets'] || {}
      elsif !self.module_info['Stage']
        self.module_info['Stage'] = {}
        self.module_info['Stage']['Payload']  = ""
        self.module_info['Stage']['Assembly'] = ""
        self.module_info['Stage']['Offsets']  = {}
      end

      @staged = true
    else
      @staged = false
    end

    # Update the module info hash with the connection type
    # that is derived from the handler for this payload.  This is
    # used for compatibility filtering purposes.
    self.module_info['ConnectionType'] = connection_type
  end

  ##
  #
  # Accessors
  #
  ##

  #
  # Returns MODULE_PAYLOAD to indicate that this is a payload module.
  #
  def self.type
    return Msf::MODULE_PAYLOAD
  end

  #
  # Returns MODULE_PAYLOAD to indicate that this is a payload module.
  #
  def type
    return Msf::MODULE_PAYLOAD
  end

  #
  # Returns the string of bad characters for this payload, if any.
  #
  def badchars
    return self.module_info['BadChars']
  end

  #
  # The list of registers that should be saved by any NOP generators or
  # encoders, if possible.
  #
  def save_registers
    return self.module_info['SaveRegisters']
  end

  #
  # Returns the type of payload, either single or staged.  Stage is
  # the default because singles and stagers are encouraged to include
  # the Single and Stager mixin which override the payload_type.
  #
  def payload_type
    return Type::Stage
  end

  #
  # Returns the string version of the payload type
  #
  def payload_type_s
    case payload_type
      when Type::Adapter
        return "adapter"
      when Type::Stage
        return "stage"
      when Type::Stager
        return "stager"
      when Type::Single
        return "single"
      else
        return "unknown"
    end
  end

  #
  # This method returns whether or not this payload uses staging.
  #
  def staged?
    (@staged or payload_type == Type::Stager or payload_type == Type::Stage)
  end

  #
  # This method returns an optional cached size value
  #
  def self.cached_size
    csize = (const_defined?('CachedSize')) ? const_get('CachedSize') : nil
    csize == :dynamic ? nil : csize
  end

  #
  # This method returns whether the payload generates variable-sized output
  #
  def self.dynamic_size?
    csize = (const_defined?('CachedSize')) ? const_get('CachedSize') : nil
    csize == :dynamic
  end

  #
  # This method returns an optional cached size value
  #
  def cached_size
      self.class.cached_size
  end

  #
  # This method returns whether the payload generates variable-sized output
  #
  def dynamic_size?
      self.class.dynamic_size?
  end

  #
  # Returns the payload's size.  If the payload is staged, the size of the
  # first stage is returned.
  #
  def size
    pl = nil
    begin
      pl = generate()
    rescue Metasploit::Framework::Compiler::Mingw::UncompilablePayloadError
    rescue NoCompatiblePayloadError
    rescue PayloadItemSizeError
    end
    pl ||= ''
    pl.length
  end

  #
  # Returns the raw payload that has not had variable substitution occur.
  #
  def payload
    return module_info['Payload'] ? module_info['Payload']['Payload'] : nil
  end

  #
  # Returns the assembly string that describes the payload if one exists.
  #
  def assembly
    return module_info['Payload'] ? module_info['Payload']['Assembly'] : nil
  end

  #
  # Sets the assembly string that describes the payload
  # If this method is used to define the payload, a payload with no offsets will be created
  #
  def assembly=(asm)
    module_info['Payload'] ||= {'Offsets' => {} }
    module_info['Payload']['Assembly'] = asm
  end

  #
  # Returns the offsets to variables that must be substitute, if any.
  #
  def offsets
    return module_info['Payload'] ? module_info['Payload']['Offsets'] : nil
  end

  #
  # Returns the compiler dependencies if the payload has one
  #
  def dependencies
    module_info['Dependencies']
  end

  #
  # Returns the staging convention that the payload uses, if any.  This is
  # used to make sure that only compatible stagers and stages are built
  # (where assumptions are made about register/environment initialization
  # state and hand-off).
  #
  def convention
    module_info['Convention']
  end

  #
  # Returns the module's connection type, such as reverse, bind, noconn,
  # or whatever else the case may be.
  #
  def connection_type
    handler_klass.general_handler_type
  end

  #
  # Returns the method used by the payload to resolve symbols for the purpose
  # of calling functions, such as ws2ord.
  #
  def symbol_lookup
    module_info['SymbolLookup']
  end

  #
  # Return the connection associated with this payload, or none if there
  # isn't one.
  #
  def handler_klass
    return module_info['Handler'] || Msf::Handler::None
  end

  #
  # Returns the session class that is associated with this payload and will
  # be used to create a session as necessary.
  #
  def session
    return module_info['Session']
  end

  ##
  #
  # Generation & variable substitution
  #
  ##

  #
  # Generates the payload and returns the raw buffer to the caller.
  # @param opts [Hash]
  def generate(opts = {})
    internal_generate(opts)
  end

  #
  # Generates the payload and returns the raw buffer to the caller,
  # handling any post-processing tasks, such as prepended code stubs.
  def generate_complete
    apply_prepends(generate)
  end

  #
  # Convert raw bytes to metasm-ready 'db' encoding format
  # eg. "\x90\xCC" => "db 0x90,0xCC"
  #
  # @param raw [Array] Byte array to encode.
  #
  def raw_to_db(raw)
    raw.unpack("C*").map {|c| "0x%.2x" % c}.join(",")
  end

  #
  # Substitutes variables with values from the module's datastore in the
  # supplied raw buffer for a given set of named offsets.  For instance,
  # RHOST is substituted with the RHOST value from the datastore which will
  # have been populated by the framework.
  #
  # Supported packing types:
  #
  # - ADDR  (foo.com, 1.2.3.4)
  # - ADDR6 (foo.com, fe80::1234:5678:8910:1234)
  # - ADDR16MSB, ADD16LSB, ADDR22MSB, ADD22LSB (foo.com, 1.2.3.4)
  #   Advanced packing types for 16/16 and 22/10 bits substitution. The 16
  #   bits types uses two offsets indicating where the 16 bits pair will be
  #   substituted, while the 22 bits types uses two offsets indicating the
  #   instructions where the 22/10 bits pair will be substituted. Normally
  #   these are offsets to "sethi" and "or" instructions on SPARC architecture.
  # - HEX   (0x12345678, "\x41\x42\x43\x44")
  # - RAW   (raw bytes)
  #
  def substitute_vars(raw, offsets)
    offsets.each_pair { |name, info|
      offset, pack = info

      # Give the derived class a chance to substitute this variable
      next if (replace_var(raw, name, offset, pack) == true)

      # Now it's our turn...
      if ((val = datastore[name]))
        if (pack == 'ADDR')
          val = Rex::Socket.resolv_nbo(val)

          # Someone gave us a funky address (ipv6?)
          if(val.length == 16)
            raise RuntimeError, "IPv6 address specified for IPv4 payload."
          end
        elsif (pack == 'ADDR6')
          val = Rex::Socket.resolv_nbo(val)

          # Convert v4 to the v6ish address
          if(val.length == 4)
            nip = "fe80::5efe:" + val.unpack("C*").join(".")
            val = Rex::Socket.resolv_nbo(nip)
          end
        elsif (['ADDR16MSB', 'ADDR16LSB', 'ADDR22MSB', 'ADDR22LSB'].include?(pack))
          val = Rex::Socket.resolv_nbo(val)

          # Someone gave us a funky address (ipv6?)
          if(val.length == 16)
            raise RuntimeError, "IPv6 address specified for IPv4 payload."
          end
        elsif (pack == 'RAW')
          # Just use the raw value...
        else
          # Check to see if the value is a hex string.  If so, convert
          # it.
          if val.kind_of?(String)
            if val =~ /^\\x/n
              val = [ val.gsub(/\\x/n, '') ].pack("H*").unpack(pack)[0]
            elsif val =~ /^0x/n
              val = val.hex
            end
          end

          # NOTE:
          # Packing assumes integer format at this point, should fix...
          val = [ val.to_i ].pack(pack)
        end

        # Substitute it
        if (['ADDR16MSB', 'ADDR16LSB'].include?(pack))
          if (offset.length != 2)
            raise RuntimeError, "Missing value for payload offset, there must be two offsets."
          end

          if (pack == 'ADDR16LSB')
            val = val.unpack('N').pack('V')
          end

          raw[offset[0], 2] = val[0, 2]
          raw[offset[1], 2] = val[2, 2]

        elsif (['ADDR22MSB', 'ADDR22LSB'].include?(pack))
          if (offset.length != 2)
            raise RuntimeError, "Missing value for payload offset, there must be two offsets."
          end

          if (pack == 'ADDR22LSB')
            val = val.unpack('N').pack('V')
          end

          hi = (0xfffffc00 & val) >> 10
          lo = 0x3ff & val

          ins = raw[offset[0], 4]
          raw[offset[0], 4] = ins | hi

          ins = raw[offset[1], 4]
          raw[offset[1], 4] = ins | lo

        else
          raw[offset, val.length] = val

        end
      else
        wlog("Missing value for payload offset #{name}, skipping.",
          'core', LEV_3)
      end
    }
  end

  #
  # Replaces an individual variable in the supplied buffer at an offset
  # using the given pack type.  This is here to allow derived payloads
  # the opportunity to replace advanced variables.
  #
  def replace_var(raw, name, offset, pack)
    return false
  end

  ##
  #
  # Shortcut methods for filtering compatible encoders
  # and NOP sleds
  #
  ##

  #
  # Returns the array of compatible encoders for this payload instance.
  #
  def compatible_encoders
    encoders = []

    framework.encoders.each_module_ranked(
      'Arch' => self.arch, 'Platform' => self.platform) { |name, mod|
      encoders << [ name, mod ]
    }

    return encoders
  end

  #
  # Returns the array of compatible nops for this payload instance.
  #
  def compatible_nops
    nops = []

    framework.nops.each_module_ranked(
      'Arch' => self.arch) { |name, mod|
      nops << [ name, mod ]
    }

    return nops
  end

  # Select a reasonable default payload and minimally configure it
  # @param [Msf::Module] mod
  def self.choose_payload(mod)
    compatible_payloads = mod.compatible_payloads(
      excluded_platforms: ['Multi'] # We don't want to select a multi payload
    ).map(&:first)

    # XXX: Determine LHOST based on global LHOST, RHOST or an arbitrary internet address
    lhost = mod.datastore['LHOST'] || Rex::Socket.source_address(mod.datastore['RHOST'] || '50.50.50.50')

    configure_payload = lambda do |payload|
      if mod.datastore.is_a?(Msf::DataStore)
        payload_defaults = { 'PAYLOAD' => payload }

        # Set LHOST if this is a reverse payload
        if payload.index('reverse')
          payload_defaults['LHOST'] = lhost
        end
        mod.datastore.import_defaults_from_hash(payload_defaults, imported_by: 'choose_payload')
      else
        mod.datastore['PAYLOAD'] = payload
        # Set LHOST if this is a reverse payload
        if payload.index('reverse')
          mod.datastore['LHOST'] = lhost
        end
      end

      payload
    end

    # If there is only one compatible payload, return it immediately
    if compatible_payloads.length == 1
      return configure_payload.call(compatible_payloads.first)
    end

    # XXX: This approach is subpar, and payloads should really be ranked!
    preferred_payloads = [
      # These payloads are generally reliable and common enough in practice
      '/meterpreter/reverse_tcp',
      '/shell/reverse_tcp',
      'cmd/unix/reverse_bash',
      'cmd/unix/reverse_netcat',
      'cmd/windows/powershell_reverse_tcp',
      # Fall back on a generic payload to autoselect a specific payload
      'generic/shell_reverse_tcp',
      'generic/shell_bind_tcp'
    ]

    # XXX: This is not efficient in the slightest
    preferred_payloads.each do |type|
      payload = compatible_payloads.find { |name| name.end_with?(type) }

      next unless payload

      return configure_payload.call(payload)
    end

    nil
  end

  #
  # A placeholder stub, to be overridden by mixins
  #
  def apply_prepends(raw)
    raw
  end

  ##
  #
  # Event notifications.
  #
  ##

  #
  # Once an exploit completes and a session has been created on behalf of the
  # payload, the framework will call the payload's on_session notification
  # routine to allow it to manipulate the session prior to handing off
  # control to the user.
  #
  def on_session(session)

    # If this payload is associated with an exploit, inform the exploit
    # that a session has been created and potentially shut down any
    # open sockets. This allows active exploits to continue hammering
    # on a service until a session is created.
    if (assoc_exploit)

      # Signal that a new session is created by calling the exploit's
      # on_new_session handler. The default behavior is to set an
      # instance variable, which the exploit will have to check.
      begin
        assoc_exploit.on_new_session(session)
      rescue ::Exception => e
        dlog("#{assoc_exploit.refname}: on_new_session handler triggered exception: #{e.class} #{e} #{e.backtrace}", 'core', LEV_1)	rescue nil
      end

      # Set the abort sockets flag only if the exploit is not passive
      # and the connection type is not 'find'
      if (
        (assoc_exploit.exploit_type == Exploit::Type::Remote) and
        (assoc_exploit.passive? == false) and
        (connection_type != 'find')
         )
         assoc_exploit.abort_sockets
      end

    end

  end

  #
  # This attribute holds the string that should be prepended to the buffer
  # when it's generated.
  #
  attr_accessor :prepend
  #
  # This attribute holds the string that should be appended to the buffer
  # when it's generated.
  #
  attr_accessor :append
  #
  # This attribute holds the string that should be prepended to the encoded
  # version of the payload (in front of the encoder as well).
  #
  attr_accessor :prepend_encoder

  #
  # If this payload is associated with an exploit, the assoc_exploit
  # attribute will point to that exploit instance.
  #
  attr_accessor :assoc_exploit

  #
  # The amount of space available to the payload, which may be nil,
  # indicating that the smallest possible payload should be used.
  #
  attr_accessor :available_space

protected

  #
  # If the payload has assembly that needs to be compiled, do so now.
  #
  # Blobs will be cached in the framework's PayloadSet
  #
  # @see PayloadSet#check_blob_cache
  # @param asm [String] Assembly code to be assembled into a raw payload
  # @param opts [Hash]
  # @return [String] The final, assembled payload
  # @raise ArgumentError if +asm+ is blank
  def build(asm, off={}, opts = {})
    if(asm.nil? or asm.empty?)
      raise ArgumentError, "Assembly must not be empty"
    end

    # Use the refname so blobs can be flushed when the module gets
    # reloaded and use the hash value to ensure that we're actually
    # getting the right blob for the given assembly.
    cache_key   = refname + asm.hash.to_s
    cache_entry = framework.payloads.check_blob_cache(cache_key)

    off.each_pair { |option, val|
      if (val[1] == 'RAW')
        asm = asm.gsub(/#{option}/){ datastore[option] }
        off.delete(option)
      end
    }

    # If there is a valid cache entry, then we don't need to worry about
    # rebuilding the assembly
    if cache_entry
      # Update the local offsets from the cache
      off.each_key { |option|
        off[option] = cache_entry[1][option]
      }

      # Return the cached payload blob
      return cache_entry[0].dup
    end

    # Assemble the payload from the assembly
    a = opts[:arch] || self.arch
    if a.kind_of? Array
      a = self.arch.first
    end
    cpu = case a
      when ARCH_X86    then Metasm::Ia32.new
      when ARCH_X64    then Metasm::X86_64.new
      when ARCH_PPC    then Metasm::PowerPC.new
      when ARCH_ARMLE  then Metasm::ARM.new
      when ARCH_MIPSLE then Metasm::MIPS.new(:little)
      when ARCH_MIPSBE then Metasm::MIPS.new(:big)
      else
        elog("Broken payload #{refname} has arch unsupported with assembly: #{module_info["Arch"].inspect}")
        elog("Call stack:\n#{caller.join("\n")}")
        return ""
      end
    sc = Metasm::Shellcode.assemble(cpu, asm).encoded

    # Calculate the actual offsets now that it's been built
    off.each_pair { |option, val|
      off[option] = [ sc.offset_of_reloc(option) || val[0], val[1] ]
    }

    # Cache the payload blob
    framework.payloads.add_blob_cache(cache_key, sc.data, off)

    # Return a duplicated copy of the assembled payload
    sc.data.dup
  end

  #
  # Generate the payload using our local payload blob and offsets
  #
  def internal_generate(opts = {})
    # Build the payload, either by using the raw payload blob defined in the
    # module or by actually assembling it
    if assembly and !assembly.empty?
      raw = build(assembly, offsets, opts)
    else
      raw = payload.dup
    end

    # If the payload is generated and there are offsets to substitute,
    # do that now.
    if (raw and offsets)
      substitute_vars(raw, offsets)
    end

    return raw
  end

  ##
  #
  # Custom merge operations for payloads
  #
  ##

  #
  # Merge the name to prefix the existing one and separate them
  # with a comma
  #
  def merge_name(info, val)
    if (info['Name'])
      info['Name'] = val + ',' + info['Name']
    else
      info['Name'] = val
    end
  end

end

end
