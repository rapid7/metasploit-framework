module FactoryBot
  module Syntax
    ## This module is a container for all strategy methods provided by
    ## FactoryBot. This includes all the default strategies provided ({Methods#build},
    ## {Methods#create}, {Methods#build_stubbed}, and {Methods#attributes_for}), as well as
    ## the complementary *_list methods.
    ## @example singular factory execution
    ##   # basic use case
    ##   build(:completed_order)
    ##
    ##   # factory yielding its result to a block
    ##   create(:post) do |post|
    ##     create(:comment, post: post)
    ##   end
    ##
    ##   # factory with attribute override
    ##   attributes_for(:post, title: "I love Ruby!")
    ##
    ##   # factory with traits and attribute override
    ##   build_stubbed(:user, :admin, :male, name: "John Doe")
    ##
    ## @example multiple factory execution
    ##   # basic use case
    ##   build_list(:completed_order, 2)
    ##   create_list(:completed_order, 2)
    ##
    ##   # factory with attribute override
    ##   attributes_for_list(:post, 4, title: "I love Ruby!")
    ##
    ##   # factory with traits and attribute override
    ##   build_stubbed_list(:user, 15, :admin, :male, name: "John Doe")
    module Methods
      # @!parse FactoryBot.register_default_strategies
      # @!method build(name, *traits_and_overrides, &block)
      # (see #strategy_method)
      # Builds a registered factory by name.
      # @return [Object] instantiated object defined by the factory

      # @!method create(name, *traits_and_overrides, &block)
      # (see #strategy_method)
      # Creates a registered factory by name.
      # @return [Object] instantiated object defined by the factory

      # @!method build_stubbed(name, *traits_and_overrides, &block)
      # (see #strategy_method)
      # Builds a stubbed registered factory by name.
      # @return [Object] instantiated object defined by the factory

      # @!method attributes_for(name, *traits_and_overrides, &block)
      # (see #strategy_method)
      # Generates a hash of attributes for a registered factory by name.
      # @return [Hash] hash of attributes for the factory

      # @!method build_list(name, amount, *traits_and_overrides)
      # (see #strategy_method_list)
      # @return [Array] array of built objects defined by the factory

      # @!method create_list(name, amount, *traits_and_overrides)
      # (see #strategy_method_list)
      # @return [Array] array of created objects defined by the factory

      # @!method build_stubbed_list(name, amount, *traits_and_overrides)
      # (see #strategy_method_list)
      # @return [Array] array of stubbed objects defined by the factory

      # @!method attributes_for_list(name, amount, *traits_and_overrides)
      # (see #strategy_method_list)
      # @return [Array<Hash>] array of attribute hashes for the factory

      # @!method strategy_method
      # @!visibility private
      # @param [Symbol] name the name of the factory to build
      # @param [Array<Symbol, Symbol, Hash>] traits_and_overrides splat args traits and a hash of overrides
      # @param [Proc] block block to be executed

      # @!method strategy_method_list
      # @!visibility private
      # @param [Symbol] name the name of the factory to execute
      # @param [Integer] amount the number of instances to execute
      # @param [Array<Symbol, Symbol, Hash>] traits_and_overrides splat args traits and a hash of overrides

      # Generates and returns the next value in a sequence.
      #
      # Arguments:
      #   name: (Symbol)
      #     The name of the sequence that a value should be generated for.
      #
      # Returns:
      #   The next value in the sequence. (Object)
      def generate(name)
        FactoryBot.sequence_by_name(name).next
      end

      # Generates and returns the list of values in a sequence.
      #
      # Arguments:
      #   name: (Symbol)
      #     The name of the sequence that a value should be generated for.
      #   count: (Fixnum)
      #     Count of values
      #
      # Returns:
      #   The next value in the sequence. (Object)
      def generate_list(name, count)
        (1..count).map do
          FactoryBot.sequence_by_name(name).next
        end
      end
    end
  end
end
