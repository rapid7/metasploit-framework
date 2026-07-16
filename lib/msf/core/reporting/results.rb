# frozen_string_literal: true

module Msf
  module Reporting
    # Typed result objects returned by every reporting method.
    module Results
      # A single-entity reporting call that successfully resolved to a
      # persisted database row (either newly created or located via
      # find-or-create).
      #
      # @!attribute [r] entity_type
      #   @return [Symbol] the kind of entity persisted (e.g. +:host+,
      #     +:service+, +:vuln+, +:session+).
      # @!attribute [r] row_id
      #   @return [Integer] the primary-key id of the persisted row.
      # @!attribute [r] row
      #   @return [ActiveRecord::Base, Object, nil] the model instance, when
      #     available. Backends that cannot return a hydrated row (e.g. the
      #     in-memory test double or remote backend) MAY pass +nil+.
      # @!attribute [r] touched
      #   @return [Boolean] true when the row pre-existed and a touched-by
      #     link was recorded; false when the row was newly created.
      Persisted = Struct.new(:entity_type, :row_id, :row, :touched, keyword_init: true) do
        def initialize(entity_type:, row_id:, row: nil, touched: false)
          super
        end

        def persisted?
          true
        end

        def skipped?
          false
        end

        def failed?
          false
        end
      end

      # A single-entity reporting call that was intentionally not executed
      # because a precondition was not satisfied.
      #
      # The canonical reason is +:db_inactive+; future reasons are added as
      # the surface grows.
      #
      # @!attribute [r] entity_type
      #   @return [Symbol]
      # @!attribute [r] reason
      #   @return [Symbol]
      Skipped = Struct.new(:entity_type, :reason, keyword_init: true) do
        def persisted?
          false
        end

        def skipped?
          true
        end

        def failed?
          false
        end
      end

      # A single-entity reporting call that attempted to persist but could
      # not. Carries a typed +Msf::Reporting::Error+ subclass; this object
      # is RETURNED, not raised.
      #
      # @!attribute [r] entity_type
      #   @return [Symbol]
      # @!attribute [r] error
      #   @return [Msf::Reporting::Error]
      Failed = Struct.new(:entity_type, :error, keyword_init: true) do
        def persisted?
          false
        end

        def skipped?
          false
        end

        def failed?
          true
        end
      end

      # A compound-pipeline step that was not executed because a required
      # parent step did not persist. Used inside +Compound#steps+ only.
      #
      # @!attribute [r] entity_type
      #   @return [Symbol]
      # @!attribute [r] parent
      #   @return [Symbol] the parent step name that prevented execution.
      SkippedDependencyFailed = Struct.new(:entity_type, :parent, keyword_init: true) do
        def persisted?
          false
        end

        def skipped?
          true
        end

        def failed?
          false
        end
      end

      # The return value of every compound reporting method.
      #
      # @!attribute [r] steps
      #   @return [Array<Persisted, Skipped, Failed, SkippedDependencyFailed>]
      #     ordered list of step results.
      # @!attribute [r] overall
      #   @return [Symbol] one of +:ok+, +:partial+, +:failed+,
      #     +:skipped_db_inactive+.
      COMPOUND_OVERALL_VALUES = %i[ok partial failed skipped_db_inactive].freeze

      Compound = Struct.new(:steps, :overall, keyword_init: true) do
        def initialize(steps:, overall:)
          unless COMPOUND_OVERALL_VALUES.include?(overall)
            raise ArgumentError, "overall must be one of #{COMPOUND_OVERALL_VALUES.inspect}, got #{overall.inspect}"
          end

          super
        end

        def ok?
          overall == :ok
        end

        def partial?
          overall == :partial
        end

        def failed?
          overall == :failed
        end

        def skipped_db_inactive?
          overall == :skipped_db_inactive
        end
      end
    end
  end
end
