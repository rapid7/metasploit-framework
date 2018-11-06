require 'rspec/support'
RSpec::Support.require_rspec_support "ruby_features"
RSpec::Support.require_rspec_support "matcher_definition"

module RSpec
  module Support
    # Extracts info about the number of arguments and allowed/required
    # keyword args of a given method.
    #
    # @private
    class MethodSignature # rubocop:disable ClassLength
      attr_reader :min_non_kw_args, :max_non_kw_args, :optional_kw_args, :required_kw_args

      def initialize(method)
        @method           = method
        @optional_kw_args = []
        @required_kw_args = []
        classify_parameters
      end

      def non_kw_args_arity_description
        case max_non_kw_args
        when min_non_kw_args then min_non_kw_args.to_s
        when INFINITY then "#{min_non_kw_args} or more"
        else "#{min_non_kw_args} to #{max_non_kw_args}"
        end
      end

      def valid_non_kw_args?(positional_arg_count, optional_max_arg_count=positional_arg_count)
        return true if positional_arg_count.nil?

        min_non_kw_args <= positional_arg_count &&
          optional_max_arg_count <= max_non_kw_args
      end

      def classify_arity(arity=@method.arity)
        if arity < 0
          # `~` inverts the one's complement and gives us the
          # number of required args
          @min_non_kw_args = ~arity
          @max_non_kw_args = INFINITY
        else
          @min_non_kw_args = arity
          @max_non_kw_args = arity
        end
      end

      if RubyFeatures.optional_and_splat_args_supported?
        def description
          @description ||= begin
            parts = []

            unless non_kw_args_arity_description == "0"
              parts << "arity of #{non_kw_args_arity_description}"
            end

            if @optional_kw_args.any?
              parts << "optional keyword args (#{@optional_kw_args.map(&:inspect).join(", ")})"
            end

            if @required_kw_args.any?
              parts << "required keyword args (#{@required_kw_args.map(&:inspect).join(", ")})"
            end

            parts << "any additional keyword args" if @allows_any_kw_args

            parts.join(" and ")
          end
        end

        def missing_kw_args_from(given_kw_args)
          @required_kw_args - given_kw_args
        end

        def invalid_kw_args_from(given_kw_args)
          return [] if @allows_any_kw_args
          given_kw_args - @allowed_kw_args
        end

        def has_kw_args_in?(args)
          Hash === args.last && could_contain_kw_args?(args)
        end

        # Without considering what the last arg is, could it
        # contain keyword arguments?
        def could_contain_kw_args?(args)
          return false if args.count <= min_non_kw_args
          @allows_any_kw_args || @allowed_kw_args.any?
        end

        def arbitrary_kw_args?
          @allows_any_kw_args
        end

        def unlimited_args?
          @max_non_kw_args == INFINITY
        end

        def classify_parameters
          optional_non_kw_args = @min_non_kw_args = 0
          @allows_any_kw_args = false

          @method.parameters.each do |(type, name)|
            case type
            # def foo(a:)
            when :keyreq  then @required_kw_args << name
            # def foo(a: 1)
            when :key     then @optional_kw_args << name
            # def foo(**kw_args)
            when :keyrest then @allows_any_kw_args = true
            # def foo(a)
            when :req     then @min_non_kw_args += 1
            # def foo(a = 1)
            when :opt     then optional_non_kw_args += 1
            # def foo(*a)
            when :rest    then optional_non_kw_args = INFINITY
            end
          end

          @max_non_kw_args = @min_non_kw_args  + optional_non_kw_args
          @allowed_kw_args = @required_kw_args + @optional_kw_args
        end
      else
        def description
          "arity of #{non_kw_args_arity_description}"
        end

        def missing_kw_args_from(_given_kw_args)
          []
        end

        def invalid_kw_args_from(_given_kw_args)
          []
        end

        def has_kw_args_in?(_args)
          false
        end

        def could_contain_kw_args?(*)
          false
        end

        def arbitrary_kw_args?
          false
        end

        def unlimited_args?
          false
        end

        alias_method :classify_parameters, :classify_arity
      end

      INFINITY = 1 / 0.0
    end

    if RSpec::Support::Ruby.jruby?
      # JRuby has only partial support for UnboundMethod#parameters, so we fall back on using #arity
      # https://github.com/jruby/jruby/issues/2816 and https://github.com/jruby/jruby/issues/2817
      if RubyFeatures.optional_and_splat_args_supported? &&
         Java::JavaLang::String.instance_method(:char_at).parameters == []

        class MethodSignature < remove_const(:MethodSignature)
        private

          def classify_parameters
            super
            if (arity = @method.arity) != 0 && @method.parameters.empty?
              classify_arity(arity)
            end
          end
        end
      end

      # JRuby used to always report -1 arity for Java proxy methods.
      # The workaround essentially makes use of Java's introspection to figure
      # out matching methods (which could be more than one partly because Java
      # supports multiple overloads, and partly because JRuby introduces
      # aliases to make method names look more Rubyesque). If there is only a
      # single match, we can use that methods arity directly instead of the
      # default -1 arity.
      #
      # This workaround only works for Java proxy methods, and in order to
      # support regular methods and blocks, we need to be careful about calling
      # owner and java_class as they might not be available
      if Java::JavaLang::String.instance_method(:char_at).arity == -1
        class MethodSignature < remove_const(:MethodSignature)
        private

          def classify_parameters
            super
            return unless @method.arity == -1
            return unless @method.respond_to?(:owner)
            return unless @method.owner.respond_to?(:java_class)
            java_instance_methods = @method.owner.java_class.java_instance_methods
            compatible_overloads = java_instance_methods.select do |java_method|
              @method == @method.owner.instance_method(java_method.name)
            end
            if compatible_overloads.size == 1
              classify_arity(compatible_overloads.first.arity)
            end
          end
        end
      end
    end

    # Encapsulates expectations about the number of arguments and
    # allowed/required keyword args of a given method.
    #
    # @api private
    class MethodSignatureExpectation
      def initialize
        @min_count = nil
        @max_count = nil
        @keywords  = []

        @expect_unlimited_arguments = false
        @expect_arbitrary_keywords  = false
      end

      attr_reader :min_count, :max_count, :keywords

      attr_accessor :expect_unlimited_arguments, :expect_arbitrary_keywords

      def max_count=(number)
        raise ArgumentError, 'must be a non-negative integer or nil' \
          unless number.nil? || (number.is_a?(Integer) && number >= 0)

        @max_count = number
      end

      def min_count=(number)
        raise ArgumentError, 'must be a non-negative integer or nil' \
          unless number.nil? || (number.is_a?(Integer) && number >= 0)

        @min_count = number
      end

      def empty?
        @min_count.nil? &&
          @keywords.to_a.empty? &&
          !@expect_arbitrary_keywords &&
          !@expect_unlimited_arguments
      end

      def keywords=(values)
        @keywords = values.to_a || []
      end
    end

    # Deals with the slightly different semantics of block arguments.
    # For methods, arguments are required unless a default value is provided.
    # For blocks, arguments are optional, even if no default value is provided.
    #
    # However, we want to treat block args as required since you virtually
    # always want to pass a value for each received argument and our
    # `and_yield` has treated block args as required for many years.
    #
    # @api private
    class BlockSignature < MethodSignature
      if RubyFeatures.optional_and_splat_args_supported?
        def classify_parameters
          super
          @min_non_kw_args = @max_non_kw_args unless @max_non_kw_args == INFINITY
        end
      end
    end

    # Abstract base class for signature verifiers.
    #
    # @api private
    class MethodSignatureVerifier
      attr_reader :non_kw_args, :kw_args, :min_non_kw_args, :max_non_kw_args

      def initialize(signature, args=[])
        @signature = signature
        @non_kw_args, @kw_args = split_args(*args)
        @min_non_kw_args = @max_non_kw_args = @non_kw_args
        @arbitrary_kw_args = @unlimited_args = false
      end

      def with_expectation(expectation) # rubocop:disable MethodLength
        return self unless MethodSignatureExpectation === expectation

        if expectation.empty?
          @min_non_kw_args = @max_non_kw_args = @non_kw_args = nil
          @kw_args     = []
        else
          @min_non_kw_args = @non_kw_args = expectation.min_count || 0
          @max_non_kw_args                = expectation.max_count || @min_non_kw_args

          if RubyFeatures.optional_and_splat_args_supported?
            @unlimited_args = expectation.expect_unlimited_arguments
          else
            @unlimited_args = false
          end

          if RubyFeatures.kw_args_supported?
            @kw_args           = expectation.keywords
            @arbitrary_kw_args = expectation.expect_arbitrary_keywords
          else
            @kw_args           = []
            @arbitrary_kw_args = false
          end
        end

        self
      end

      def valid?
        missing_kw_args.empty? &&
          invalid_kw_args.empty? &&
          valid_non_kw_args? &&
          arbitrary_kw_args? &&
          unlimited_args?
      end

      def error_message
        if missing_kw_args.any?
          "Missing required keyword arguments: %s" % [
            missing_kw_args.join(", ")
          ]
        elsif invalid_kw_args.any?
          "Invalid keyword arguments provided: %s" % [
            invalid_kw_args.join(", ")
          ]
        elsif !valid_non_kw_args?
          "Wrong number of arguments. Expected %s, got %s." % [
            @signature.non_kw_args_arity_description,
            non_kw_args
          ]
        end
      end

    private

      def valid_non_kw_args?
        @signature.valid_non_kw_args?(min_non_kw_args, max_non_kw_args)
      end

      def missing_kw_args
        @signature.missing_kw_args_from(kw_args)
      end

      def invalid_kw_args
        @signature.invalid_kw_args_from(kw_args)
      end

      def arbitrary_kw_args?
        !@arbitrary_kw_args || @signature.arbitrary_kw_args?
      end

      def unlimited_args?
        !@unlimited_args || @signature.unlimited_args?
      end

      def split_args(*args)
        kw_args = if @signature.has_kw_args_in?(args)
                    args.pop.keys
                  else
                    []
                  end

        [args.length, kw_args]
      end
    end

    # Figures out wether a given method can accept various arguments.
    # Surprisingly non-trivial.
    #
    # @private
    StrictSignatureVerifier = MethodSignatureVerifier

    # Allows matchers to be used instead of providing keyword arguments. In
    # practice, when this happens only the arity of the method is verified.
    #
    # @private
    class LooseSignatureVerifier < MethodSignatureVerifier
    private

      def split_args(*args)
        if RSpec::Support.is_a_matcher?(args.last) && @signature.could_contain_kw_args?(args)
          args.pop
          @signature = SignatureWithKeywordArgumentsMatcher.new(@signature)
        end

        super(*args)
      end

      # If a matcher is used in a signature in place of keyword arguments, all
      # keyword argument validation needs to be skipped since the matcher is
      # opaque.
      #
      # Instead, keyword arguments will be validated when the method is called
      # and they are actually known.
      #
      # @private
      class SignatureWithKeywordArgumentsMatcher
        def initialize(signature)
          @signature = signature
        end

        def missing_kw_args_from(_kw_args)
          []
        end

        def invalid_kw_args_from(_kw_args)
          []
        end

        def non_kw_args_arity_description
          @signature.non_kw_args_arity_description
        end

        def valid_non_kw_args?(*args)
          @signature.valid_non_kw_args?(*args)
        end

        def has_kw_args_in?(args)
          @signature.has_kw_args_in?(args)
        end
      end
    end
  end
end
