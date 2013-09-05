# -*- coding: binary -*-
require 'resolv'
require 'msf/core'
require 'rex/socket'

module Msf

###
#
# The base class for all options.
#
###
class OptBase

  #
  # Initializes a named option with the supplied attribute array.
  # The array is composed of three values.
  #
  # attrs[0] = required (boolean type)
  # attrs[1] = description (string)
  # attrs[2] = default value
  # attrs[3] = possible enum values
  #
  def initialize(in_name, attrs = [])
    self.name     = in_name
    self.advanced = false
    self.evasion  = false
    self.required = attrs[0] || false
    self.desc     = attrs[1]
    self.default  = attrs[2]
    self.enums    = [ *(attrs[3]) ].map { |x| x.to_s }
  end

  #
  # Returns true if this is a required option.
  #
  def required?
    return required
  end

  #
  # Returns true if this is an advanced option.
  #
  def advanced?
    return advanced
  end

  #
  # Returns true if this is an evasion option.
  #
  def evasion?
    return evasion
  end

  #
  # Returns true if the supplied type is equivalent to this option's type.
  #
  def type?(in_type)
    return (type == in_type)
  end

  #
  # If it's required and the value is nil or empty, then it's not valid.
  #
  def valid?(value)
    return (required? and (value == nil or value.to_s.empty?)) ? false : true
  end

  #
  # Returns true if the value supplied is nil and it's required to be
  # a valid value
  #
  def empty_required_value?(value)
    return (required? and value.nil?)
  end

  #
  # Normalizes the supplied value to conform with the type that the option is
  # conveying.
  #
  def normalize(value)
    value
  end

  #
  # Returns a string representing a user-friendly display of the chosen value
  #
  def display_value(value)
    value.to_s
  end

  #
  # The name of the option.
  #
  attr_reader   :name
  #
  # Whether or not the option is required.
  #
  attr_reader   :required
  #
  # The description of the option.
  #
  attr_reader   :desc
  #
  # The default value of the option.
  #
  attr_reader   :default
  #
  # Storing the name of the option.
  #
  attr_writer   :name
  #
  # Whether or not this is an advanced option.
  #
  attr_accessor :advanced
  #
  # Whether or not this is an evasion option.
  #
  attr_accessor :evasion
  #
  # The module or entity that owns this option.
  #
  attr_accessor :owner
  #
  # The list of potential valid values
  #
  attr_accessor :enums

protected

  attr_writer   :required, :desc, :default # :nodoc:
end

###
#
# Core option types.  The core supported option types are:
#
# OptString  - Multi-byte character string
# OptRaw     - Multi-byte raw string
# OptBool    - Boolean true or false indication
# OptPort    - TCP/UDP service port
# OptAddress - IP address or hostname
# OptPath    - Path name on disk or an Object ID
# OptInt     - An integer value
# OptEnum    - Select from a set of valid values
# OptAddressRange - A subnet or range of addresses
# OptSession - A session identifier
# OptRegexp  - Valid Ruby regular expression
#
###

###
#
# Mult-byte character string option.
#
###
class OptString < OptBase
  def type
    return 'string'
  end

  def normalize(value)
    if (value =~ /^file:(.*)/)
      path = $1
      begin
        value = File.read(path)
      rescue ::Errno::ENOENT, ::Errno::EISDIR
        value = nil
      end
    end
    value
  end

  def valid?(value=self.value)
    value = normalize(value)
    return false if empty_required_value?(value)
    return super
  end
end

###
#
# Raw, arbitrary data option.
#
###
class OptRaw < OptBase
  def type
    return 'raw'
  end

  def normalize(value)
    if (value =~ /^file:(.*)/)
      path = $1
      begin
        value = File.read(path)
      rescue ::Errno::ENOENT, ::Errno::EISDIR
        value = nil
      end
    end
    value
  end

  def valid?(value=self.value)
    value = normalize(value)
    return false if empty_required_value?(value)
    return super
  end
end

###
#
# Boolean option.
#
###
class OptBool < OptBase

  TrueRegex = /^(y|yes|t|1|true)$/i

  def type
    return 'bool'
  end

  def valid?(value)
    return false if empty_required_value?(value)

    if ((value != nil and
        (value.to_s.empty? == false) and
        (value.to_s.match(/^(y|yes|n|no|t|f|0|1|true|false)$/i) == nil)))
      return false
    end

    true
  end

  def normalize(value)
    if(value.nil? or value.to_s.match(TrueRegex).nil?)
      false
    else
      true
    end
  end

  def is_true?(value)
    return normalize(value)
  end

  def is_false?(value)
    return !is_true?(value)
  end

end

###
#
# Enum option.
#
###
class OptEnum < OptBase

  def type
    return 'enum'
  end

  def valid?(value=self.value)
    return false if empty_required_value?(value)
    return true if value.nil? and !required?

    (value and self.enums.include?(value.to_s))
  end

  def normalize(value=self.value)
    return nil if not self.valid?(value)
    return value.to_s
  end

  def desc=(value)
    self.desc_string = value

    self.desc
  end

  def desc
    if self.enums
      str = self.enums.join(', ')
    end
    "#{self.desc_string || ''} (accepted: #{str})"
  end


protected

  attr_accessor :desc_string # :nodoc:

end

###
#
# Network port option.
#
###
class OptPort < OptBase
  def type
    return 'port'
  end

  def normalize(value)
    value.to_i
  end

  def valid?(value)
    return false if empty_required_value?(value)

    if ((value != nil and value.to_s.empty? == false) and
        ((value.to_s.match(/^\d+$/) == nil or value.to_i < 0 or value.to_i > 65535)))
      return false
    end

    return super
  end
end

###
#
# Network address option.
#
###
class OptAddress < OptBase
  def type
    return 'address'
  end

  def valid?(value)
    return false if empty_required_value?(value)
    return false unless value.kind_of?(String) or value.kind_of?(NilClass)

    if (value != nil and value.empty? == false)
      begin
        getaddr_result = ::Rex::Socket.getaddress(value, true)
        # Covers a wierdcase where an incomplete ipv4 address will have it's
        # missing octets filled in  with 0's. (e.g 192.168 become 192.0.0.168)
        # which does not feel like a legit behaviour
        if value =~ /^\d{1,3}(\.\d{1,3}){1,3}$/
          return false unless value =~ Rex::Socket::MATCH_IPV4
        end
      rescue
        return false
      end
    end

    return super
  end
end

###
#
# Network address range option.
#
###
class OptAddressRange < OptBase
  def type
    return 'addressrange'
  end

  def normalize(value)
    return nil unless value.kind_of?(String)
    if (value =~ /^file:(.*)/)
      path = $1
      return false if not File.exists?(path) or File.directory?(path)
      return File.readlines(path).map{ |s| s.strip}.join(" ")
    elsif (value =~ /^rand:(.*)/)
      count = $1.to_i
      return false if count < 1
      ret = ''
      count.times {
        ret << " " if not ret.empty?
        ret << [ rand(0x100000000) ].pack("N").unpack("C*").map{|x| x.to_s }.join(".")
      }
      return ret
    end
    return value
  end

  def valid?(value)
    return false if empty_required_value?(value)
    return false unless value.kind_of?(String) or value.kind_of?(NilClass)

    if (value != nil and value.empty? == false)
      normalized = normalize(value)
      return false if normalized.nil?
      walker = Rex::Socket::RangeWalker.new(normalized)
      if (not walker or not walker.valid?)
        return false
      end
    end

    return super
  end
end

###
#
# File system path option.
#
###
class OptPath < OptBase
  def type
    return 'path'
  end

  # Generally, 'value' should be a file that exists.
  def valid?(value)
    return false if empty_required_value?(value)
    if value and !value.empty?
      if value =~ /^memory:\s*([0-9]+)/i
        return false unless check_memory_location($1)
      else
        unless File.exists?(value)
          return false
        end
      end
    end
    return super
  end

  # The AuthBrute mixin can take a memory address as well --
  # currently, no other OptFile can make use of these objects.
  # TODO: Implement memory:xxx to be more generally useful so
  # the validator on OptFile isn't lying for non-AuthBrute.
  def check_memory_location(id)
    return false unless self.class.const_defined?(:ObjectSpace)
    obj = ObjectSpace._id2ref(id.to_i) rescue nil
    return false unless obj.respond_to? :acts_as_file?
    return false unless obj.acts_as_file? # redundant?
    return !!obj
  end

end

###
#
# Integer option.
#
###
class OptInt < OptBase
  def type
    return 'integer'
  end

  def normalize(value)
    if (value.to_s.match(/^0x[a-fA-F\d]+$/))
      value.to_i(16)
    else
      value.to_i
    end
  end

  def valid?(value)
    return super if !required? and value.to_s.empty?
    return false if empty_required_value?(value)

    if value and not value.to_s.match(/^0x[0-9a-fA-F]+$|^-?\d+$/)
      return false
    end

    return super
  end
end

###
#
# Regexp option
#
###
class OptRegexp < OptBase
  def type
    return 'regexp'
  end

  def valid?(value)
    unless super
      return false
    end
    return true if (not required? and value.nil?)

    begin
      Regexp.compile(value)

      return true
    rescue RegexpError, TypeError
      return false
    end
  end

  def normalize(value)
    return nil if value.nil?
    return Regexp.compile(value)
  end

  def display_value(value)
    if value.kind_of?(Regexp)
      return value.source
    elsif value.kind_of?(String)
      return display_value(normalize(value))
    end

    return super
  end
end

###
#
# The options purpose in life is to associate named options
# with arbitrary values at the most simplistic level.  Each
# module contains a OptionContainer that is used to hold the
# various options that the module depends on.  Example of options
# that are stored in the OptionContainer are rhost and rport for
# payloads or exploits that need to connect to a host and
# port, for instance.
#
###
class OptionContainer < Hash

  #
  # Merges in the supplied options and converts them to a OptBase
  # as necessary.
  #
  def initialize(opts = {})
    self.sorted = []

    add_options(opts)
  end

  #
  # Return the value associated with the supplied name.
  #
  def [](name)
    return get(name)
  end

  #
  # Return the option associated with the supplied name.
  #
  def get(name)
    begin
      return fetch(name)
    rescue
    end
  end

  #
  # Returns whether or not the container has any options,
  # excluding advanced (and evasions).
  #
  def has_options?
    each_option { |name, opt|
      return true if (opt.advanced? == false)

    }

    return false
  end

  #
  # Returns whether or not the container has any advanced
  # options.
  #
  def has_advanced_options?
    each_option { |name, opt|
      return true if (opt.advanced? == true)
    }

    return false
  end

  #
  # Returns whether or not the container has any evasion
  # options.
  #
  def has_evasion_options?
    each_option { |name, opt|
      return true if (opt.evasion? == true)
    }

    return false
  end

  #
  # Removes an option.
  #
  def remove_option(name)
    delete(name)
    sorted.each_with_index { |e, idx|
      sorted[idx] = nil if (e[0] == name)
    }
    sorted.delete(nil)
  end

  #
  # Adds one or more options.
  #
  def add_options(opts, owner = nil, advanced = false, evasion = false)
    return false if (opts == nil)

    if (opts.kind_of?(Array))
      add_options_array(opts, owner, advanced, evasion)
    else
      add_options_hash(opts, owner, advanced, evasion)
    end
  end

  #
  # Add options from a hash of names.
  #
  def add_options_hash(opts, owner = nil, advanced = false, evasion = false)
    opts.each_pair { |name, opt|
      add_option(opt, name, owner, advanced, evasion)
    }
  end

  #
  # Add options from an array of option instances or arrays.
  #
  def add_options_array(opts, owner = nil, advanced = false, evasion = false)
    opts.each { |opt|
      add_option(opt, nil, owner, advanced, evasion)
    }
  end

  #
  # Adds an option.
  #
  def add_option(option, name = nil, owner = nil, advanced = false, evasion = false)
    if (option.kind_of?(Array))
      option = option.shift.new(name, option)
    elsif (!option.kind_of?(OptBase))
      raise ArgumentError,
        "The option named #{name} did not come in a compatible format.",
        caller
    end

    option.advanced = advanced
    option.evasion  = evasion
    option.owner    = owner

    self.store(option.name, option)

    # Re-calculate the sorted list
    self.sorted = self.sort
  end

  #
  # Alias to add advanced options that sets the proper state flag.
  #
  def add_advanced_options(opts, owner = nil)
    return false if (opts == nil)

    add_options(opts, owner, true)
  end

  #
  # Alias to add evasion options that sets the proper state flag.
  #
  def add_evasion_options(opts, owner = nil)
    return false if (opts == nil)

    add_options(opts, owner, false, true)
  end

  #
  # Make sures that each of the options has a value of a compatible
  # format and that all the required options are set.
  #
  def validate(datastore)
    errors = []

    each_pair { |name, option|
      if (!option.valid?(datastore[name]))
        errors << name
      # If the option is valid, normalize its format to the correct type.
      elsif ((val = option.normalize(datastore[name])) != nil)
        # This *will* result in a module that previously used the
        # global datastore to have its local datastore set, which
        # means that changing the global datastore and re-running
        # the same module will now use the newly-normalized local
        # datastore value instead. This is mostly mitigated by
        # forcing a clone through mod.replicant, but can break
        # things in corner cases.
        datastore[name] = val
      end
    }

    if (errors.empty? == false)
      raise OptionValidateError.new(errors),
        "One or more options failed to validate", caller
    end

    return true
  end

  #
  # Creates string of options that were used from the datastore in VAR=VAL
  # format separated by commas.
  #
  def options_used_to_s(datastore)
    used = ''

    each_pair { |name, option|
      next if (datastore[name] == nil)

      used += ", " if (used.length > 0)
      used += "#{name}=#{datastore[name]}"
    }

    return used
  end

  #
  # Enumerates each option name
  #
  def each_option(&block)
    each_pair(&block)
  end

  #
  # Overrides the builtin 'each' operator to avoid the following exception on Ruby 1.9.2+
  #    "can't add a new key into hash during iteration"
  #
  def each(&block)
    list = []
    self.keys.sort.each do |sidx|
      list << [sidx, self[sidx]]
    end
    list.each(&block)
  end

  #
  # Merges the options in this container with another option container and
  # returns the sorted results.
  #
  def merge_sort(other_container)
    result = self.dup

    other_container.each { |name, opt|
      if (result.get(name) == nil)
        result[name] = opt
      end
    }

    result.sort
  end

  #
  # The sorted array of options.
  #
  attr_reader :sorted

protected

  attr_writer :sorted # :nodoc:

end

#
# Builtin framework options with shortcut methods
#
module Opt

@@builtin_opts =
  {
    'RHOST' => [ OptAddress, 'nil',   true,  '"The target address"' ],
    'RPORT' => [ OptPort,    'nil',   true,  '"The target port"' ],
    'LHOST' => [ OptAddress, 'nil',   true,  '"The listen address"' ],
    'LPORT' => [ OptPort,    'nil',   true,  '"The listen port"' ],
    'CPORT' => [ OptPort,    'nil',   false, '"The local client port"' ],
    'CHOST' => [ OptAddress, 'nil',   false, '"The local client address"' ],
    'Proxies' => [ OptString, 'nil',  'false', '"Use a proxy chain"']
  }

#
# Build the builtin_xyz methods on the fly using the type information for each
# of the builtin framework options, such as RHOST.
#
class <<self
  @@builtin_opts.each_pair { |opt, info|
    eval(
      "
      def builtin_#{opt.downcase}(default = #{info[1]}, required = #{info[2]}, desc = #{info[3]})
        #{info[0]}.new('#{opt}', [ required, desc, default ])
      end

      alias #{opt} builtin_#{opt.downcase}
      ")
  }
end

#
# Define the constant versions of the options which are merely redirections to
# the class methods.
#
@@builtin_opts.each_pair { |opt, info|
  eval("#{opt} = Msf::Opt::builtin_#{opt.downcase}")
}

end

end

