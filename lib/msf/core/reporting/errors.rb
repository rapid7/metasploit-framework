# frozen_string_literal: true

module Msf
  module Reporting
    # Base class of every reporting-layer error. Never raised directly.
    #
    # Subclasses split on intent:
    # * +ValidationError+    — bad caller input; ALWAYS raised at the call
    #   site.
    # * +CompoundError+      — partial / failed compound pipeline; raised
    #   unless +raise_on_failure: false+.
    # * +DetachedSessionError+ — operation attempted on a session whose DB
    #   row failed to persist.
    # * +BackendError+       — transport / persistence-layer failure;
    #   carried inside +Failed+, NEVER raised by single-entity methods.
    class Error < StandardError; end

    # Raised when caller-supplied kwargs are missing, of the wrong type, not
    # in an enumerated set, or in mutual conflict.
    #
    # @!attribute [r] field
    #   @return [Symbol, nil] the offending kwarg, when applicable.
    # @!attribute [r] fields
    #   @return [Array<Symbol>, nil] the offending kwargs, for +:conflict+.
    # @!attribute [r] reason
    #   @return [Symbol] one of +:missing+, +:type+, +:enum+, +:conflict+,
    #     +:deprecated+.
    # @!attribute [r] expected
    #   @return [Object, nil] expected type, for +reason: :type+.
    # @!attribute [r] got
    #   @return [Object, nil] supplied value, for +:type+ / +:enum+.
    # @!attribute [r] allowed
    #   @return [Array, nil] allowed values, for +reason: :enum+.
    class ValidationError < Error
      attr_reader :field, :fields, :reason, :expected, :got, :allowed

      def initialize(message = nil, field: nil, fields: nil, reason: nil, expected: nil, got: nil, allowed: nil)
        @field = field
        @fields = fields
        @reason = reason
        @expected = expected
        @got = got
        @allowed = allowed
        super(message || default_message)
      end

      private

      def default_message
        case @reason
        when :missing
          "missing required kwarg #{@field.inspect}"
        when :type
          "kwarg #{@field.inspect} expected #{@expected.inspect}, got #{@got.class}"
        when :enum
          "kwarg #{@field.inspect} not in #{@allowed.inspect} (got #{@got.inspect})"
        when :conflict
          "conflicting kwargs: #{Array(@fields).inspect}"
        when :deprecated
          "kwarg #{@field.inspect} is deprecated"
        else
          'reporting validation failed'
        end
      end
    end

    # Raised by compound pipeline calls when the overall outcome is
    # +:partial+ or +:failed+ and the caller did not pass
    # +raise_on_failure: false+. Carries the +Compound+ result whose
    # +steps+ enumerate per-step typed errors.
    #
    # @!attribute [r] result
    #   @return [Msf::Reporting::Results::Compound]
    class CompoundError < Error
      attr_reader :result

      def initialize(result, message = nil)
        @result = result
        super(message || "compound reporting overall=#{@result&.overall.inspect}")
      end
    end

    # Raised when a reporting call (typically +report_session_event+) is
    # made against a session whose +Mdm::Session+ row failed to persist.
    # The in-memory session remains fully alive; the framework only
    # refuses to record events against it.
    class DetachedSessionError < Error; end

    # Base class for transport / persistence-layer failures. Carried
    # inside +Failed+ results and never raised by single-entity methods.
    class BackendError < Error; end

    # The DB layer is currently inactive. Returned (not raised) inside a
    # +Skipped(reason: :db_inactive)+ result on the first call after the
    # DB drops, and on every subsequent call until recovery.
    class DbInactiveError < BackendError; end

    # The remote +RemoteDataService+ proxy could not be reached or
    # returned a transport-layer error.
    class RemoteServiceError < BackendError; end
  end
end
