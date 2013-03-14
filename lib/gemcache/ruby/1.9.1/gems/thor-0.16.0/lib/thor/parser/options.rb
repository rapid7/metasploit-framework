class Thor
  class Options < Arguments #:nodoc:
    LONG_RE     = /^(--\w+(?:-\w+)*)$/
    SHORT_RE    = /^(-[a-z])$/i
    EQ_RE       = /^(--\w+(?:-\w+)*|-[a-z])=(.*)$/i
    SHORT_SQ_RE = /^-([a-z]{2,})$/i # Allow either -x -v or -xv style for single char args
    SHORT_NUM   = /^(-[a-z])#{NUMERIC}$/i

    # Receives a hash and makes it switches.
    def self.to_switches(options)
      options.map do |key, value|
        case value
          when true
            "--#{key}"
          when Array
            "--#{key} #{value.map{ |v| v.inspect }.join(' ')}"
          when Hash
            "--#{key} #{value.map{ |k,v| "#{k}:#{v}" }.join(' ')}"
          when nil, false
            ""
          else
            "--#{key} #{value.inspect}"
        end
      end.join(" ")
    end

    # Takes a hash of Thor::Option and a hash with defaults.
    def initialize(hash_options={}, defaults={})
      options = hash_options.values
      super(options)

      # Add defaults
      defaults.each do |key, value|
        @assigns[key.to_s] = value
        @non_assigned_required.delete(hash_options[key])
      end

      @shorts, @switches, @extra = {}, {}, []

      options.each do |option|
        @switches[option.switch_name] = option

        option.aliases.each do |short|
          @shorts[short.to_s] ||= option.switch_name
        end
      end
    end

    def remaining
      @extra
    end

    def parse(args)
      @pile = args.dup

      while peek
        match, is_switch = current_is_switch?
        shifted = shift

        if is_switch
          case shifted
            when SHORT_SQ_RE
              unshift($1.split('').map { |f| "-#{f}" })
              next
            when EQ_RE, SHORT_NUM
              unshift($2)
              switch = $1
            when LONG_RE, SHORT_RE
              switch = $1
          end

          switch = normalize_switch(switch)
          option = switch_option(switch)
          @assigns[option.human_name] = parse_peek(switch, option)
        elsif match
          @extra << shifted
          @extra << shift while peek && peek !~ /^-/
        else
          @extra << shifted
        end
      end

      check_requirement!

      assigns = Thor::CoreExt::HashWithIndifferentAccess.new(@assigns)
      assigns.freeze
      assigns
    end

    def check_unknown!
      # an unknown option starts with - or -- and has no more --'s afterward.
      unknown = @extra.select { |str| str =~ /^--?(?:(?!--).)*$/ }
      raise UnknownArgumentError, "Unknown switches '#{unknown.join(', ')}'" unless unknown.empty?
    end

    protected

      # Returns true if the current value in peek is a registered switch.
      #
      def current_is_switch?
        case peek
        when LONG_RE, SHORT_RE, EQ_RE, SHORT_NUM
          [true, switch?($1)]
        when SHORT_SQ_RE
          [true, $1.split('').any? { |f| switch?("-#{f}") }]
        else
          [false, false]
        end
      end

      def current_is_switch_formatted?
        case peek
        when LONG_RE, SHORT_RE, EQ_RE, SHORT_NUM, SHORT_SQ_RE
          true
        else
          false
        end
      end

      def switch?(arg)
        switch_option(normalize_switch(arg))
      end

      def switch_option(arg)
        if match = no_or_skip?(arg)
          @switches[arg] || @switches["--#{match}"]
        else
          @switches[arg]
        end
      end

      # Check if the given argument is actually a shortcut.
      #
      def normalize_switch(arg)
        (@shorts[arg] || arg).tr('_', '-')
      end

      # Parse boolean values which can be given as --foo=true, --foo or --no-foo.
      #
      def parse_boolean(switch)
        if current_is_value?
          if ["true", "TRUE", "t", "T", true].include?(peek)
            shift
            true
          elsif ["false", "FALSE", "f", "F", false].include?(peek)
            shift
            false
          else
            true
          end
        else
          @switches.key?(switch) || !no_or_skip?(switch)
        end
      end

      # Parse the value at the peek analyzing if it requires an input or not.
      #
      def parse_peek(switch, option)
        if current_is_switch_formatted? || last?
          if option.boolean?
            # No problem for boolean types
          elsif no_or_skip?(switch)
            return nil # User set value to nil
          elsif option.string? && !option.required?
            # Return the default if there is one, else the human name
            return option.lazy_default || option.default || option.human_name
          elsif option.lazy_default
            return option.lazy_default
          else
            raise MalformattedArgumentError, "No value provided for option '#{switch}'"
          end
        end

        @non_assigned_required.delete(option)
        send(:"parse_#{option.type}", switch)
      end
  end
end
