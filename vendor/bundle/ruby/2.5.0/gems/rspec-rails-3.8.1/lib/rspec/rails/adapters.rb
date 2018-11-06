require 'delegate'
require 'active_support'
require 'active_support/concern'
require 'active_support/core_ext/string'

module RSpec
  module Rails
    # @private
    def self.disable_testunit_autorun
      # `Test::Unit::AutoRunner.need_auto_run=` was introduced to the test-unit
      # gem in version 2.4.9. Previous to this version `Test::Unit.run=` was
      # used. The implementation of test-unit included with Ruby has neither
      # method.
      if defined?(Test::Unit::AutoRunner.need_auto_run = ())
        Test::Unit::AutoRunner.need_auto_run = false
      elsif defined?(Test::Unit.run = ())
        Test::Unit.run = false
      end
    end
    private_class_method :disable_testunit_autorun

    if ::Rails::VERSION::STRING >= '4.1.0'
      if defined?(Kernel.gem)
        gem 'minitest'
      else
        require 'minitest'
      end
      require 'minitest/assertions'
      # Constant aliased to either Minitest or TestUnit, depending on what is
      # loaded.
      Assertions = Minitest::Assertions
    elsif RUBY_VERSION >= '2.2.0'
      # Minitest / TestUnit has been removed from ruby core. However, we are
      # on an old Rails version and must load the appropriate gem
      if ::Rails::VERSION::STRING >= '4.0.0'
        # ActiveSupport 4.0.x has the minitest '~> 4.2' gem as a dependency
        # This gem has no `lib/minitest.rb` file.
        gem 'minitest' if defined?(Kernel.gem)
        require 'minitest/unit'
        Assertions = MiniTest::Assertions
      elsif ::Rails::VERSION::STRING >= '3.2.21'
        # TODO: Change the above check to >= '3.2.22' once it's released
        begin
          # Test::Unit "helpfully" sets up autoload for its `AutoRunner`.
          # While we do not reference it directly, when we load the `TestCase`
          # classes from AS (ActiveSupport), AS kindly references `AutoRunner`
          # for everyone.
          #
          # To handle this we need to pre-emptively load 'test/unit' and make
          # sure the version installed has `AutoRunner` (the 3.x line does to
          # date). If so, we turn the auto runner off.
          require 'test/unit'
          require 'test/unit/assertions'
          disable_testunit_autorun
        rescue LoadError => e
          raise LoadError, <<-ERR.squish, e.backtrace
            Ruby 2.2+ has removed test/unit from the core library. Rails
            requires this as a dependency. Please add test-unit gem to your
            Gemfile: `gem 'test-unit', '~> 3.0'` (#{e.message})"
          ERR
        end
        Assertions = Test::Unit::Assertions
      else
        abort <<-MSG.squish
          Ruby 2.2+ is not supported on Rails #{::Rails::VERSION::STRING}.
          Check the Rails release notes for the appropriate update with
          support.
        MSG
      end
    else
      begin
        require 'test/unit/assertions'
      rescue LoadError
        # work around for Rubinius not having a std std-lib
        require 'rubysl-test-unit' if defined?(RUBY_ENGINE) && RUBY_ENGINE == 'rbx'
        require 'test/unit/assertions'
      end
      # Turn off test unit's auto runner for those using the gem
      disable_testunit_autorun
      # Constant aliased to either Minitest or TestUnit, depending on what is
      # loaded.
      Assertions = Test::Unit::Assertions
    end

    # @private
    class AssertionDelegator < Module
      def initialize(*assertion_modules)
        assertion_class = Class.new(SimpleDelegator) do
          include ::RSpec::Rails::Assertions
          include ::RSpec::Rails::MinitestCounters
          assertion_modules.each { |mod| include mod }
        end

        super() do
          define_method :build_assertion_instance do
            assertion_class.new(self)
          end

          def assertion_instance
            @assertion_instance ||= build_assertion_instance
          end

          assertion_modules.each do |mod|
            mod.public_instance_methods.each do |method|
              next if method == :method_missing || method == "method_missing"
              define_method(method.to_sym) do |*args, &block|
                assertion_instance.send(method.to_sym, *args, &block)
              end
            end
          end
        end
      end
    end

    # Adapts example groups for `Minitest::Test::LifecycleHooks`
    #
    # @private
    module MinitestLifecycleAdapter
      extend ActiveSupport::Concern

      included do |group|
        group.before { after_setup }
        group.after  { before_teardown }

        group.around do |example|
          before_setup
          example.run
          after_teardown
        end
      end

      def before_setup
      end

      def after_setup
      end

      def before_teardown
      end

      def after_teardown
      end
    end

    # @private
    module MinitestCounters
      attr_writer :assertions
      def assertions
        @assertions ||= 0
      end
    end

    # @private
    module SetupAndTeardownAdapter
      extend ActiveSupport::Concern

      module ClassMethods
        # Wraps `setup` calls from within Rails' testing framework in `before`
        # hooks.
        def setup(*methods, &block)
          methods.each do |method|
            if method.to_s =~ /^setup_(with_controller|fixtures|controller_request_and_response)$/
              prepend_before { __send__ method }
            else
              before         { __send__ method }
            end
          end
          before(&block) if block
        end

        # @api private
        #
        # Wraps `teardown` calls from within Rails' testing framework in
        # `after` hooks.
        def teardown(*methods, &block)
          methods.each { |method| after { __send__ method } }
          after(&block) if block
        end
      end

      def initialize(*args)
        super
        @example = nil
      end

      def method_name
        @example
      end
    end

    # @private
    module MinitestAssertionAdapter
      extend ActiveSupport::Concern

      # @private
      module ClassMethods
        # Returns the names of assertion methods that we want to expose to
        # examples without exposing non-assertion methods in Test::Unit or
        # Minitest.
        def assertion_method_names
          methods = ::RSpec::Rails::Assertions.
            public_instance_methods.
            select do |m|
              m.to_s =~ /^(assert|flunk|refute)/
            end
          methods + test_unit_specific_methods
        end

        def define_assertion_delegators
          assertion_method_names.each do |m|
            define_method(m.to_sym) do |*args, &block|
              assertion_delegator.send(m.to_sym, *args, &block)
            end
          end
        end

        # Starting on Rails 4, Minitest is the default testing framework so no
        # need to add TestUnit specific methods.
        if ::Rails::VERSION::STRING >= '4.0.0'
          def test_unit_specific_methods
            []
          end
        else
          def test_unit_specific_methods
            [:build_message]
          end
        end
      end

      class AssertionDelegator
        include ::RSpec::Rails::Assertions
        include ::RSpec::Rails::MinitestCounters
      end

      def assertion_delegator
        @assertion_delegator ||= AssertionDelegator.new
      end

      included do
        define_assertion_delegators
      end
    end

    # Backwards compatibility. It's unlikely that anyone is using this
    # constant, but we had forgotten to mark it as `@private` earlier
    #
    # @private
    TestUnitAssertionAdapter = MinitestAssertionAdapter
  end
end
