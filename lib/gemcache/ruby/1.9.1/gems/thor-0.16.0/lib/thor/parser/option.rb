class Thor
  class Option < Argument #:nodoc:
    attr_reader :aliases, :group, :lazy_default, :hide

    VALID_TYPES = [:boolean, :numeric, :hash, :array, :string]

    def initialize(name, options={})
      options[:required] = false unless options.key?(:required)
      super
      @lazy_default = options[:lazy_default]
      @group        = options[:group].to_s.capitalize if options[:group]
      @aliases      = Array(options[:aliases])
      @hide         = options[:hide]
    end

    # This parse quick options given as method_options. It makes several
    # assumptions, but you can be more specific using the option method.
    #
    #   parse :foo => "bar"
    #   #=> Option foo with default value bar
    #
    #   parse [:foo, :baz] => "bar"
    #   #=> Option foo with default value bar and alias :baz
    #
    #   parse :foo => :required
    #   #=> Required option foo without default value
    #
    #   parse :foo => 2
    #   #=> Option foo with default value 2 and type numeric
    #
    #   parse :foo => :numeric
    #   #=> Option foo without default value and type numeric
    #
    #   parse :foo => true
    #   #=> Option foo with default value true and type boolean
    #
    # The valid types are :boolean, :numeric, :hash, :array and :string. If none
    # is given a default type is assumed. This default type accepts arguments as
    # string (--foo=value) or booleans (just --foo).
    #
    # By default all options are optional, unless :required is given.
    #
    def self.parse(key, value)
      if key.is_a?(Array)
        name, *aliases = key
      else
        name, aliases = key, []
      end

      name    = name.to_s
      default = value

      type = case value
      when Symbol
        default = nil
        if VALID_TYPES.include?(value)
          value
        elsif required = (value == :required)
          :string
        end
      when TrueClass, FalseClass
        :boolean
      when Numeric
        :numeric
      when Hash, Array, String
        value.class.name.downcase.to_sym
      end
      self.new(name.to_s, :required => required, :type => type, :default => default, :aliases => aliases)
    end

    def switch_name
      @switch_name ||= dasherized? ? name : dasherize(name)
    end

    def human_name
      @human_name ||= dasherized? ? undasherize(name) : name
    end

    def usage(padding=0)
      sample = if banner && !banner.to_s.empty?
        "#{switch_name}=#{banner}"
      else
        switch_name
      end

      sample = "[#{sample}]" unless required?

      if aliases.empty?
        (" " * padding) << sample
      else
        "#{aliases.join(', ')}, #{sample}"
      end
    end

    VALID_TYPES.each do |type|
      class_eval <<-RUBY, __FILE__, __LINE__ + 1
        def #{type}?
          self.type == #{type.inspect}
        end
      RUBY
    end

  protected

    def validate!
      raise ArgumentError, "An option cannot be boolean and required." if boolean? && required?
    end

    def dasherized?
      name.index('-') == 0
    end

    def undasherize(str)
      str.sub(/^-{1,2}/, '')
    end

    def dasherize(str)
      (str.length > 1 ? "--" : "-") + str.gsub('_', '-')
    end
  end
end
