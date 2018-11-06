module RSpec
  module Mocks
    # @private
    module TargetDelegationClassMethods
      def delegate_to(matcher_method)
        define_method(:to) do |matcher, &block|
          unless matcher_allowed?(matcher)
            raise_unsupported_matcher(:to, matcher)
          end
          define_matcher(matcher, matcher_method, &block)
        end
      end

      def delegate_not_to(matcher_method, options={})
        method_name = options.fetch(:from)
        define_method(method_name) do |matcher, &block|
          case matcher
          when Matchers::Receive, Matchers::HaveReceived
            define_matcher(matcher, matcher_method, &block)
          when Matchers::ReceiveMessages, Matchers::ReceiveMessageChain
            raise_negation_unsupported(method_name, matcher)
          else
            raise_unsupported_matcher(method_name, matcher)
          end
        end
      end

      def disallow_negation(method_name)
        define_method(method_name) do |matcher, *_args|
          raise_negation_unsupported(method_name, matcher)
        end
      end
    end

    # @private
    module TargetDelegationInstanceMethods
      attr_reader :target

    private

      def matcher_allowed?(matcher)
        Matchers::Matcher === matcher
      end

      def define_matcher(matcher, name, &block)
        matcher.__send__(name, target, &block)
      end

      def raise_unsupported_matcher(method_name, matcher)
        raise UnsupportedMatcherError,
              "only the `receive`, `have_received` and `receive_messages` matchers are supported " \
              "with `#{expression}(...).#{method_name}`, but you have provided: #{matcher}"
      end

      def raise_negation_unsupported(method_name, matcher)
        raise NegationUnsupportedError,
              "`#{expression}(...).#{method_name} #{matcher.name}` is not supported since it " \
              "doesn't really make sense. What would it even mean?"
      end
    end

    # @private
    class TargetBase
      def initialize(target)
        @target = target
      end

      extend TargetDelegationClassMethods
      include TargetDelegationInstanceMethods
    end

    # @private
    module ExpectationTargetMethods
      extend TargetDelegationClassMethods
      include TargetDelegationInstanceMethods

      delegate_to :setup_expectation
      delegate_not_to :setup_negative_expectation, :from => :not_to
      delegate_not_to :setup_negative_expectation, :from => :to_not

      def expression
        :expect
      end
    end

    # @private
    class ExpectationTarget < TargetBase
      include ExpectationTargetMethods
    end

    # @private
    class AllowanceTarget < TargetBase
      def expression
        :allow
      end

      delegate_to :setup_allowance
      disallow_negation :not_to
      disallow_negation :to_not
    end

    # @private
    class AnyInstanceAllowanceTarget < TargetBase
      def expression
        :allow_any_instance_of
      end

      delegate_to :setup_any_instance_allowance
      disallow_negation :not_to
      disallow_negation :to_not
    end

    # @private
    class AnyInstanceExpectationTarget < TargetBase
      def expression
        :expect_any_instance_of
      end

      delegate_to :setup_any_instance_expectation
      delegate_not_to :setup_any_instance_negative_expectation, :from => :not_to
      delegate_not_to :setup_any_instance_negative_expectation, :from => :to_not
    end
  end
end
