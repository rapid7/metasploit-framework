# frozen_string_literal: true
module YARD
  # Generalized options class for passing around large amounts of options between objects.
  #
  # The options class exists for better visibility and documentability of options being
  # passed through to other objects. Because YARD has parser and template architectures
  # that are heavily reliant on options, it is necessary to make these option keys easily
  # visible and understood by developers. Since the options class is more than just a
  # basic Hash, the subclass can provide aliasing and convenience methods to simplify
  # option property access, and, if needed, support backward-compatibility for deprecated
  # key names.
  #
  # == Hash and OpenStruct-like Access
  #
  # Although the options class allows for Hash-like access (<tt>opts[:key]</tt>), the recommended
  # mechanism for accessing an option key will be via standard method calls on attributes
  #
  # The options class can also act as an open ended key value storage structure (like a
  # Hash or OpenStruct), and allows for setting and getting of unregistered option keys.
  # This methodology is not recommended, however, and is only supported for backward
  # compatibility inside YARD. Whenever possible, developers should define all keys used
  # by an options class.
  #
  # == Declaring Default Values
  #
  # Note that the options class can contain default value definitions for certain options,
  # but to initialize these defaults, {#reset_defaults} must be called manually after
  # initialization; the options object is always created empty until defaults are applied.
  #
  # @abstract Subclasses should define (and document) custom attributes that are expected
  #   to be made available as option keys.
  # @example Defining an Options class with custom option keys
  #   class TemplateOptions < YARD::Options
  #     # @return [Symbol] the output format to generate templates in
  #     attr_accessor :format
  #
  #     # @return [Symbol] the template to use when generating output
  #     attr_accessor :template
  #   end
  # @example Initializing default option values
  #   class TemplateOptions < YARD::Options
  #     def reset_defaults
  #       super
  #       self.format = :html
  #       self.template = :default
  #       self.highlight = true
  #       # ...
  #     end
  #   end
  # @example Using +default_attr+ to create default attributes
  #   class TemplateOptions < YARD::Options
  #     default_attr :format, :html
  #     default_attr :template, :default
  #     default_attr :highlight, true
  #   end
  # @example Deprecating an option while still supporting it
  #   class TemplateOptions < YARD::Options
  #     # @return [Boolean] if syntax highlighting should be performed on code blocks.
  #     #   Defaults to true.
  #     attr_accessor :highlight
  #
  #     # @deprecated Use {#highlight} instead.
  #     # @return [Boolean] if no syntax highlighting should be performs on code blocks.
  #     #   Defaults to false.
  #     attr_accessor :no_highlight
  #     def no_highlight=(value) @highlight = !value end
  #     def no_highlight; !highlight end
  #   end
  class Options
    # @!macro [attach] yard.default_attr
    #   @!attribute $1
    # Defines an attribute named +key+ and sets a default value for it
    #
    # @example Defining a default option key
    #   default_attr :name, 'Default Name'
    #   default_attr :time, lambda { Time.now }
    # @param [Symbol] key the option key name
    # @param [Object, Proc] default the default object value. If the default
    #   value is a proc, it is executed upon initialization.
    def self.default_attr(key, default)
      (@defaults ||= {})[key] = default
      attr_accessor(key)
    end

    # Delegates calls with Hash syntax to actual method with key name
    #
    # @example Calling on an option key with Hash syntax
    #   options[:format] # equivalent to: options.format
    # @param [Symbol, String] key the option name to access
    # @return the value of the option named +key+
    def [](key) send(key) end

    # Delegates setter calls with Hash syntax to the attribute setter with the key name
    #
    # @example Setting an option with Hash syntax
    #   options[:format] = :html # equivalent to: options.format = :html
    # @param [Symbol, String] key the optin to set
    # @param [Object] value the value to set for the option
    # @return [Object] the value being set
    def []=(key, value) send("#{key}=", value) end

    # Updates values from an options hash or options object on this object.
    # All keys passed should be key names defined by attributes on the class.
    #
    # @example Updating a set of options on an Options object
    #   opts.update(:template => :guide, :type => :fulldoc)
    # @param [Hash, Options] opts
    # @return [self]
    def update(opts)
      opts = opts.to_hash if Options === opts
      opts.each do |key, value|
        self[key] = value
      end
      self
    end

    # Creates a new options object and sets options hash or object value
    # onto that object.
    #
    # @param [Options, Hash] opts
    # @return [Options] the newly created options object
    # @see #update
    def merge(opts)
      dup.update(opts)
    end

    # @return [Hash] Converts options object to an options hash. All keys
    #   will be symbolized.
    def to_hash
      opts = {}
      instance_variables.each do |ivar|
        name = ivar.to_s.sub(/^@/, '')
        opts[name.to_sym] = send(name)
      end
      opts
    end

    # Yields over every option key and value
    # @yield [key, value] every option key and value
    # @yieldparam [Symbol] key the option key
    # @yieldparam [Object] value the option value
    # @return [void]
    def each
      instance_variables.each do |ivar|
        name = ivar.to_s.sub(/^@/, '')
        yield(name.to_sym, send(name))
      end
    end

    # Inspects the object
    def inspect
      "<#{self.class}: #{to_hash.inspect}>"
    end

    # @return [Boolean] whether another Options object equals the
    #   keys and values of this options object
    def ==(other)
      case other
      when Options; to_hash == other.to_hash
      when Hash; to_hash == other
      else false
      end
    end

    # Handles setting and accessing of unregistered keys similar
    # to an OpenStruct object.
    #
    # @note It is not recommended to set and access unregistered keys on
    #   an Options object. Instead, register the attribute before using it.
    def method_missing(meth, *args, &block)
      if meth.to_s =~ /^(.+)=$/
        log.debug "Attempting to set unregistered key #{$1} on #{self.class}"
        instance_variable_set("@#{$1}", args.first)
      elsif args.empty?
        log.debug "Attempting to access unregistered key #{meth} on #{self.class}"
        instance_variable_defined?("@#{meth}") ? instance_variable_get("@#{meth}") : nil
      else
        super
      end
    end

    # Resets all values to their defaults.
    #
    # @abstract Subclasses should override this method to perform custom
    #   value initialization if not using {default_attr}. Be sure to call
    #   +super+ so that default initialization can take place.
    # @return [void]
    def reset_defaults
      names_set = {}
      self.class.ancestors.each do |klass| # look at all ancestors
        defaults =
          klass.instance_variable_defined?("@defaults") &&
          klass.instance_variable_get("@defaults")
        next unless defaults
        defaults.each do |key, value|
          next if names_set[key]
          names_set[key] = true
          self[key] = Proc === value ? value.call : value
        end
      end
    end

    # Deletes an option value for +key+
    #
    # @param [Symbol, String] key the key to delete a value for
    # @return [Object] the value that was deleted
    def delete(key)
      val = self[key]
      if instance_variable_defined?("@#{key}")
        remove_instance_variable("@#{key}")
      end
      val
    end

    def tap; yield(self); self end unless defined?(tap) # only for 1.8.6
  end
end
