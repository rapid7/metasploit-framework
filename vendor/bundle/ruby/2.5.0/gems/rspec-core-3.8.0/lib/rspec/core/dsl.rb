module RSpec
  module Core
    # DSL defines methods to group examples, most notably `describe`,
    # and exposes them as class methods of {RSpec}. They can also be
    # exposed globally (on `main` and instances of `Module`) through
    # the {Configuration} option `expose_dsl_globally`.
    #
    # By default the methods `describe`, `context` and `example_group`
    # are exposed. These methods define a named context for one or
    # more examples. The given block is evaluated in the context of
    # a generated subclass of {RSpec::Core::ExampleGroup}.
    #
    # ## Examples:
    #
    #     RSpec.describe "something" do
    #       context "when something is a certain way" do
    #         it "does something" do
    #           # example code goes here
    #         end
    #       end
    #     end
    #
    # @see ExampleGroup
    # @see ExampleGroup.example_group
    module DSL
      # @private
      def self.example_group_aliases
        @example_group_aliases ||= []
      end

      # @private
      def self.exposed_globally?
        @exposed_globally ||= false
      end

      # @private
      def self.expose_example_group_alias(name)
        return if example_group_aliases.include?(name)

        example_group_aliases << name

        (class << RSpec; self; end).__send__(:define_method, name) do |*args, &example_group_block|
          group = RSpec::Core::ExampleGroup.__send__(name, *args, &example_group_block)
          RSpec.world.record(group)
          group
        end

        expose_example_group_alias_globally(name) if exposed_globally?
      end

      class << self
        # @private
        attr_accessor :top_level
      end

      # Adds the describe method to Module and the top level binding.
      # @api private
      def self.expose_globally!
        return if exposed_globally?

        example_group_aliases.each do |method_name|
          expose_example_group_alias_globally(method_name)
        end

        @exposed_globally = true
      end

      # Removes the describe method from Module and the top level binding.
      # @api private
      def self.remove_globally!
        return unless exposed_globally?

        example_group_aliases.each do |method_name|
          change_global_dsl { undef_method method_name }
        end

        @exposed_globally = false
      end

      # @private
      def self.expose_example_group_alias_globally(method_name)
        change_global_dsl do
          remove_method(method_name) if method_defined?(method_name)
          define_method(method_name) { |*a, &b| ::RSpec.__send__(method_name, *a, &b) }
        end
      end

      # @private
      def self.change_global_dsl(&changes)
        (class << top_level; self; end).class_exec(&changes)
        Module.class_exec(&changes)
      end
    end
  end
end

# Capture main without an eval.
::RSpec::Core::DSL.top_level = self
