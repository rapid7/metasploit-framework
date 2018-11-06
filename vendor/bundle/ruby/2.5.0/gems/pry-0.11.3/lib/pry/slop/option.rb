class Pry::Slop
  class Option

    # The default Hash of configuration options this class uses.
    DEFAULT_OPTIONS = {
      :argument => false,
      :optional_argument => false,
      :tail => false,
      :default => nil,
      :callback => nil,
      :delimiter => ',',
      :limit => 0,
      :match => nil,
      :optional => true,
      :required => false,
      :as => String,
      :autocreated => false
    }

    attr_reader :short, :long, :description, :config, :types
    attr_accessor :count, :argument_in_value

    # Incapsulate internal option information, mainly used to store
    # option specific configuration data, most of the meat of this
    # class is found in the #value method.
    #
    # slop        - The instance of Slop tied to this Option.
    # short       - The String or Symbol short flag.
    # long        - The String or Symbol long flag.
    # description - The String description text.
    # config      - A Hash of configuration options.
    # block       - An optional block used as a callback.
    def initialize(slop, short, long, description, config = {}, &block)
      @slop = slop
      @short = short
      @long = long
      @description = description
      @config = DEFAULT_OPTIONS.merge(config)
      @count = 0
      @callback = block_given? ? block : config[:callback]
      @value = nil

      @types = {
        :string  => proc { |v| v.to_s },
        :symbol  => proc { |v| v.to_sym },
        :integer => proc { |v| value_to_integer(v) },
        :float   => proc { |v| value_to_float(v) },
        :range   => proc { |v| value_to_range(v) },
        :count   => proc { |v| @count }
      }

      if long && long.size > @slop.config[:longest_flag]
        @slop.config[:longest_flag] = long.size
      end

      @config.each_key do |key|
        predicate = :"#{key}?"
        unless self.class.method_defined? predicate
          self.class.__send__(:define_method, predicate) { !!@config[key] }
        end
      end
    end

    # Returns true if this option expects an argument.
    def expects_argument?
      config[:argument] && config[:argument] != :optional
    end

    # Returns true if this option accepts an optional argument.
    def accepts_optional_argument?
      config[:optional_argument] || config[:argument] == :optional
    end

    # Returns the String flag of this option. Preferring the long flag.
    def key
      long || short
    end

    # Call this options callback if one exists, and it responds to call().
    #
    # Returns nothing.
    def call(*objects)
      @callback.call(*objects) if @callback.respond_to?(:call)
    end

    # Set the new argument value for this option.
    #
    # We use this setter method to handle concatenating lists. That is,
    # when an array type is specified and used more than once, values from
    # both options will be grouped together and flattened into a single array.
    def value=(new_value)
      if config[:as].to_s.downcase == 'array'
        @value ||= []

        if new_value.respond_to?(:split)
          @value.concat new_value.split(config[:delimiter], config[:limit])
        end
      else
        @value = new_value
      end
    end

    # Fetch the argument value for this option.
    #
    # Returns the Object once any type conversions have taken place.
    def value
      value = @value.nil? ? config[:default] : @value

      if [true, false, nil].include?(value) && config[:as].to_s != 'count'
        return value
      end

      type = config[:as]
      if type.respond_to?(:call)
        type.call(value)
      else
        if callable = types[type.to_s.downcase.to_sym]
          callable.call(value)
        else
          value
        end
      end
    end

    # Returns the help String for this option.
    def to_s
      return config[:help] if config[:help].respond_to?(:to_str)

      out = "    #{short ? "-#{short}, " : ' ' * 4}"

      if long
        out << "--#{long}"
        size = long.size
        diff = @slop.config[:longest_flag] - size
        out << (' ' * (diff + 6))
      else
        out << (' ' * (@slop.config[:longest_flag] + 8))
      end

      "#{out}#{description}"
    end
    alias help to_s

    # Returns the String inspection text.
    def inspect
      "#<Slop::Option [-#{short} | --#{long}" +
      "#{'=' if expects_argument?}#{'=?' if accepts_optional_argument?}]" +
      " (#{description}) #{config.inspect}"
    end

    private

    # Convert an object to an Integer if possible.
    #
    # value - The Object we want to convert to an integer.
    #
    # Returns the Integer value if possible to convert, else a zero.
    def value_to_integer(value)
      if @slop.strict?
        begin
          Integer(value.to_s, 10)
        rescue ArgumentError
          raise InvalidArgumentError, "#{value} could not be coerced into Integer"
        end
      else
        value.to_s.to_i
      end
    end

    # Convert an object to a Float if possible.
    #
    # value - The Object we want to convert to a float.
    #
    # Returns the Float value if possible to convert, else a zero.
    def value_to_float(value)
      if @slop.strict?
        begin
          Float(value.to_s)
        rescue ArgumentError
          raise InvalidArgumentError, "#{value} could not be coerced into Float"
        end
      else
        value.to_s.to_f
      end
    end

    # Convert an object to a Range if possible.
    #
    # value - The Object we want to convert to a range.
    #
    # Returns the Range value if one could be found, else the original object.
    def value_to_range(value)
      case value.to_s
      when /\A(\-?\d+)\z/
        Range.new($1.to_i, $1.to_i)
      when /\A(-?\d+?)(\.\.\.?|-|,)(-?\d+)\z/
        Range.new($1.to_i, $3.to_i, $2 == '...')
      else
        if @slop.strict?
          raise InvalidArgumentError, "#{value} could not be coerced into Range"
        else
          value
        end
      end
    end

  end
end
