# -*- coding: binary -*-

require 'rex/post/hwbridge/extension'
require 'rex/post/hwbridge/object_aliases'

module Rex
module Post
module HWBridge

# Used for merging constants from extensions
module Extensions
end

class Client
  @@ext_hash = {}

  #
  # Checks the extension hash to see if a class has already been associated
  # with the supplied extension name.
  #
  def self.check_ext_hash(name)
    @@ext_hash[name]
  end

  #
  # Stores the name to class association for the supplied extension name.
  #
  def self.set_ext_hash(name, klass)
    @@ext_hash[name] = klass
  end

  #
  # Initializes the client context
  #
  def initialize(sock,opts={})
    init_hwbridge(sock,opts)
  end

  #
  # Initialize the hwbridge instance
  #
  def init_hwbridge(sock,opts={})
    self.sock        = sock
    self.ext         = ObjectAliases.new
    self.ext_aliases = ObjectAliases.new
  end

  #
  # sends request through 'exploit' which is the hwbridge/connect
  #
  def send_request(uri)
    if not exploit
      $stdout.puts("Exploit module not connected")
      return {}
    end
    exploit.fetch_json(uri)
  end

  #
  # Gets/refreshes HW status & capabilities
  #
  def get_status
    send_request("/status")
  end

  #
  # Gets the devices statistics
  #
  def get_statistics
    send_request("/statistics")
  end

  #
  # Fetches custom methods from HW, if any
  #
  def get_custom_methods
    send_request("/custom_methods")
  end

  #
  # Sends a reset signal to the device to perform a software bounce or a full
  # factory reset.  Depends on how the device decided to handle it.
  #
  def reset
    send_request("/control/factory_reset")
  end

  #
  # Sends a reboot signal to reboot the device.
  #
  def reboot
    send_request("/control/reboot")
  end

  ##
  #
  # Alias processor
  #
  ##

  #
  # Translates unhandled methods into registered extension aliases
  # if a matching extension alias exists for the supplied symbol.
  #
  def method_missing(symbol, *args)
    self.ext_aliases.aliases[symbol.to_s]
  end

  ##
  #
  # Extension registration
  #
  ##

  #
  # Loads the client half of the supplied extension and initializes it as a
  # registered extension that can be reached through client.ext.[extension].
  #
  def add_extension(name, commands=[])
    self.commands |= commands

    # Check to see if this extension has already been loaded.
    if ((klass = self.class.check_ext_hash(name.downcase)) == nil)
      old = Rex::Post::HWBridge::Extensions.constants
      require("rex/post/hwbridge/extensions/#{name.downcase}/#{name.downcase}")
      new = Rex::Post::HWBridge::Extensions.constants

      # No new constants added?
      if ((diff = new - old).empty?)
        diff = [ name.capitalize ]
      end

      klass = Rex::Post::HWBridge::Extensions.const_get(diff[0]).const_get(diff[0])

      # Save the module name to class association now that the code is
      # loaded.
      self.class.set_ext_hash(name.downcase, klass)
    end

    # Create a new instance of the extension
    inst = klass.new(self)

    self.ext.aliases[inst.name] = inst

    return true
  end

  #
  # Deregisters an extension alias of the supplied name.
  #
  def deregister_extension(name)
    self.ext.aliases.delete(name)
  end

  #
  # Enumerates all of the loaded extensions.
  #
  def each_extension(&block)
    self.ext.aliases.each(block)
  end

  #
  # Registers an aliased extension that can be referenced through
  # client.name.
  #
  def register_extension_alias(name, ext)
    self.ext_aliases.aliases[name] = ext
    # Whee!  Syntactic sugar, where art thou?
    #
    # Create an instance method on this object called +name+ that returns
    # +ext+.  We have to do it this way instead of simply
    # self.class.class_eval so that other meterpreter sessions don't get
    # extension methods when this one does
    (class << self; self; end).class_eval do
      define_method(name.to_sym) do
        ext
      end
    end
    ext
  end

  #
  # Registers zero or more aliases that are provided in an array.
  #
  def register_extension_aliases(aliases)
    aliases.each { |a|
      register_extension_alias(a['name'], a['ext'])
    }
  end

  #
  # Deregisters a previously registered extension alias.
  #
  def deregister_extension_alias(name)
    self.ext_aliases.aliases.delete(name)
  end

  #
  # Dumps the extension tree.
  #
  def dump_extension_tree()
    items = []
    items.concat(self.ext.dump_alias_tree('client.ext'))
    items.concat(self.ext_aliases.dump_alias_tree('client'))

    return items.sort
  end

  #
  # Encodes (or not) a UTF-8 string
  #
  def unicode_filter_encode(str)
    self.encode_unicode ? Rex::Text.unicode_filter_encode(str) : str
  end

  #
  # Decodes (or not) a UTF-8 string
  #
  def unicode_filter_decode(str)
    self.encode_unicode ? Rex::Text.unicode_filter_decode(str) : str
  end

  # A list of the commands
  #
  attr_reader :commands
  attr_reader :ext, :sock
protected
  attr_writer   :commands # :nodoc:
  attr_accessor :ext_aliases # :nodoc:
  attr_writer   :ext, :sock # :nodoc:

end

###
#
# Exception thrown when a request fails.
#
###
class RequestError < ArgumentError
  def initialize(method, einfo, ecode=nil)
    @method = method
    @result = einfo
    @code   = ecode || einfo
  end

  def to_s
    "#{@method}: Operation failed: #{@result}"
  end

  # The method that failed.
  attr_reader :method

  # The error result that occurred, typically a windows error message.
  attr_reader :result

  # The error result that occurred, typically a windows error code.
  attr_reader :code
end

end
end
end
