RSpec::Support.require_rspec_support 'recursive_const_methods'

module RSpec
  module Mocks
    # Provides information about constants that may (or may not)
    # have been mutated by rspec-mocks.
    class Constant
      extend Support::RecursiveConstMethods

      # @api private
      def initialize(name)
        @name = name
        @previously_defined = false
        @stubbed = false
        @hidden = false
        @valid_name = true
        yield self if block_given?
      end

      # @return [String] The fully qualified name of the constant.
      attr_reader :name

      # @return [Object, nil] The original value (e.g. before it
      #   was mutated by rspec-mocks) of the constant, or
      #   nil if the constant was not previously defined.
      attr_accessor :original_value

      # @private
      attr_writer :previously_defined, :stubbed, :hidden, :valid_name

      # @return [Boolean] Whether or not the constant was defined
      #   before the current example.
      def previously_defined?
        @previously_defined
      end

      # @return [Boolean] Whether or not rspec-mocks has mutated
      #   (stubbed or hidden) this constant.
      def mutated?
        @stubbed || @hidden
      end

      # @return [Boolean] Whether or not rspec-mocks has stubbed
      #   this constant.
      def stubbed?
        @stubbed
      end

      # @return [Boolean] Whether or not rspec-mocks has hidden
      #   this constant.
      def hidden?
        @hidden
      end

      # @return [Boolean] Whether or not the provided constant name
      #   is a valid Ruby constant name.
      def valid_name?
        @valid_name
      end

      # The default `to_s` isn't very useful, so a custom version is provided.
      def to_s
        "#<#{self.class.name} #{name}>"
      end
      alias inspect to_s

      # @private
      def self.unmutated(name)
        previously_defined = recursive_const_defined?(name)
      rescue NameError
        new(name) do |c|
          c.valid_name = false
        end
      else
        new(name) do |const|
          const.previously_defined = previously_defined
          const.original_value = recursive_const_get(name) if previously_defined
        end
      end

      # Queries rspec-mocks to find out information about the named constant.
      #
      # @param [String] name the name of the constant
      # @return [Constant] an object contaning information about the named
      #   constant.
      def self.original(name)
        mutator = ::RSpec::Mocks.space.constant_mutator_for(name)
        mutator ? mutator.to_constant : unmutated(name)
      end
    end

    # Provides a means to stub constants.
    class ConstantMutator
      extend Support::RecursiveConstMethods

      # Stubs a constant.
      #
      # @param (see ExampleMethods#stub_const)
      # @option (see ExampleMethods#stub_const)
      # @return (see ExampleMethods#stub_const)
      #
      # @see ExampleMethods#stub_const
      # @note It's recommended that you use `stub_const` in your
      #  examples. This is an alternate public API that is provided
      #  so you can stub constants in other contexts (e.g. helper
      #  classes).
      def self.stub(constant_name, value, options={})
        unless String === constant_name
          raise ArgumentError, "`stub_const` requires a String, but you provided a #{constant_name.class.name}"
        end

        mutator = if recursive_const_defined?(constant_name, &raise_on_invalid_const)
                    DefinedConstantReplacer
                  else
                    UndefinedConstantSetter
                  end

        mutate(mutator.new(constant_name, value, options[:transfer_nested_constants]))
        value
      end

      # Hides a constant.
      #
      # @param (see ExampleMethods#hide_const)
      #
      # @see ExampleMethods#hide_const
      # @note It's recommended that you use `hide_const` in your
      #  examples. This is an alternate public API that is provided
      #  so you can hide constants in other contexts (e.g. helper
      #  classes).
      def self.hide(constant_name)
        mutate(ConstantHider.new(constant_name, nil, {}))
        nil
      end

      # Contains common functionality used by all of the constant mutators.
      #
      # @private
      class BaseMutator
        include Support::RecursiveConstMethods

        attr_reader :original_value, :full_constant_name

        def initialize(full_constant_name, mutated_value, transfer_nested_constants)
          @full_constant_name        = normalize_const_name(full_constant_name)
          @mutated_value             = mutated_value
          @transfer_nested_constants = transfer_nested_constants
          @context_parts             = @full_constant_name.split('::')
          @const_name                = @context_parts.pop
          @reset_performed           = false
        end

        def to_constant
          const = Constant.new(full_constant_name)
          const.original_value = original_value

          const
        end

        def idempotently_reset
          reset unless @reset_performed
          @reset_performed = true
        end
      end

      # Hides a defined constant for the duration of an example.
      #
      # @private
      class ConstantHider < BaseMutator
        def mutate
          return unless (@defined = recursive_const_defined?(full_constant_name))
          @context = recursive_const_get(@context_parts.join('::'))
          @original_value = get_const_defined_on(@context, @const_name)

          @context.__send__(:remove_const, @const_name)
        end

        def to_constant
          return Constant.unmutated(full_constant_name) unless @defined

          const = super
          const.hidden = true
          const.previously_defined = true

          const
        end

        def reset
          return unless @defined
          @context.const_set(@const_name, @original_value)
        end
      end

      # Replaces a defined constant for the duration of an example.
      #
      # @private
      class DefinedConstantReplacer < BaseMutator
        def initialize(*args)
          super
          @constants_to_transfer = []
        end

        def mutate
          @context = recursive_const_get(@context_parts.join('::'))
          @original_value = get_const_defined_on(@context, @const_name)

          @constants_to_transfer = verify_constants_to_transfer!

          @context.__send__(:remove_const, @const_name)
          @context.const_set(@const_name, @mutated_value)

          transfer_nested_constants
        end

        def to_constant
          const = super
          const.stubbed = true
          const.previously_defined = true

          const
        end

        def reset
          @constants_to_transfer.each do |const|
            @mutated_value.__send__(:remove_const, const)
          end

          @context.__send__(:remove_const, @const_name)
          @context.const_set(@const_name, @original_value)
        end

        def transfer_nested_constants
          @constants_to_transfer.each do |const|
            @mutated_value.const_set(const, get_const_defined_on(original_value, const))
          end
        end

        def verify_constants_to_transfer!
          return [] unless should_transfer_nested_constants?

          { @original_value => "the original value", @mutated_value => "the stubbed value" }.each do |value, description|
            next if value.respond_to?(:constants)

            raise ArgumentError,
                  "Cannot transfer nested constants for #{@full_constant_name} " \
                  "since #{description} is not a class or module and only classes " \
                  "and modules support nested constants."
          end

          if Array === @transfer_nested_constants
            @transfer_nested_constants = @transfer_nested_constants.map(&:to_s) if RUBY_VERSION == '1.8.7'
            undefined_constants = @transfer_nested_constants - constants_defined_on(@original_value)

            if undefined_constants.any?
              available_constants = constants_defined_on(@original_value) - @transfer_nested_constants
              raise ArgumentError,
                    "Cannot transfer nested constant(s) #{undefined_constants.join(' and ')} " \
                    "for #{@full_constant_name} since they are not defined. Did you mean " \
                    "#{available_constants.join(' or ')}?"
            end

            @transfer_nested_constants
          else
            constants_defined_on(@original_value)
          end
        end

        def should_transfer_nested_constants?
          return true  if @transfer_nested_constants
          return false unless RSpec::Mocks.configuration.transfer_nested_constants?
          @original_value.respond_to?(:constants) && @mutated_value.respond_to?(:constants)
        end
      end

      # Sets an undefined constant for the duration of an example.
      #
      # @private
      class UndefinedConstantSetter < BaseMutator
        def mutate
          @parent = @context_parts.inject(Object) do |klass, name|
            if const_defined_on?(klass, name)
              get_const_defined_on(klass, name)
            else
              ConstantMutator.stub(name_for(klass, name), Module.new)
            end
          end

          @parent.const_set(@const_name, @mutated_value)
        end

        def to_constant
          const = super
          const.stubbed = true
          const.previously_defined = false

          const
        end

        def reset
          @parent.__send__(:remove_const, @const_name)
        end

      private

        def name_for(parent, name)
          root = if parent == Object
                   ''
                 else
                   parent.name
                 end
          root + '::' + name
        end
      end

      # Uses the mutator to mutate (stub or hide) a constant. Ensures that
      # the mutator is correctly registered so it can be backed out at the end
      # of the test.
      #
      # @private
      def self.mutate(mutator)
        ::RSpec::Mocks.space.register_constant_mutator(mutator)
        mutator.mutate
      end

      # Used internally by the constant stubbing to raise a helpful
      # error when a constant like "A::B::C" is stubbed and A::B is
      # not a module (and thus, it's impossible to define "A::B::C"
      # since only modules can have nested constants).
      #
      # @api private
      def self.raise_on_invalid_const
        lambda do |const_name, failed_name|
          raise "Cannot stub constant #{failed_name} on #{const_name} " \
                "since #{const_name} is not a module."
        end
      end
    end
  end
end
