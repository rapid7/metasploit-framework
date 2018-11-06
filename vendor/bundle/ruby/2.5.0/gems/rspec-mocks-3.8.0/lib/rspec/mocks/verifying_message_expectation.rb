RSpec::Support.require_rspec_support 'method_signature_verifier'

module RSpec
  module Mocks
    # A message expectation that knows about the real implementation of the
    # message being expected, so that it can verify that any expectations
    # have the valid arguments.
    # @api private
    class VerifyingMessageExpectation < MessageExpectation
      # A level of indirection is used here rather than just passing in the
      # method itself, since method look up is expensive and we only want to
      # do it if actually needed.
      #
      # Conceptually the method reference makes more sense as a constructor
      # argument since it should be immutable, but it is significantly more
      # straight forward to build the object in pieces so for now it stays as
      # an accessor.
      attr_accessor :method_reference

      def initialize(*args)
        super
      end

      # @private
      def with(*args, &block)
        super(*args, &block).tap do
          validate_expected_arguments! do |signature|
            example_call_site_args = [:an_arg] * signature.min_non_kw_args
            example_call_site_args << :kw_args_hash if signature.required_kw_args.any?
            @argument_list_matcher.resolve_expected_args_based_on(example_call_site_args)
          end
        end
      end

    private

      def validate_expected_arguments!
        return if method_reference.nil?

        method_reference.with_signature do |signature|
          args     = yield signature
          verifier = Support::LooseSignatureVerifier.new(signature, args)

          unless verifier.valid?
            # Fail fast is required, otherwise the message expectation will fail
            # as well ("expected method not called") and clobber this one.
            @failed_fast = true
            @error_generator.raise_invalid_arguments_error(verifier)
          end
        end
      end
    end
  end
end
