# frozen_string_literal: true

module Msf
  module Reporting
    module Backends
      # Reporting backend backed by the local +Msf::DBManager+ (the default
      # driver used by msfconsole when a PostgreSQL connection is
      # configured).
      #
      # Only the single-entity methods that have been migrated to this
      # backend are implemented as delegating shims; calling any other
      # reporting method falls through to the +Msf::Reporting::Reporter+
      # stub surface, which returns +Skipped(reason: :not_implemented)+.
      class DbManagerBackend
        # @return [Msf::Framework]
        attr_reader :framework

        # @param framework [Msf::Framework] host framework whose
        #   +#db+ accessor returns an active +Msf::DBManager+.
        def initialize(framework:)
          @framework = framework
        end

        # Persist or find-or-create a host row.
        #
        # Accepts the same opts-hash shape +Msf::DBManager#report_host+
        # accepts, and translates the contract's +address:+ kwarg into
        # the +:host+ key before delegating.
        #
        # @param address [String, ::Mdm::Host] required.
        # @param kwargs additional opts forwarded verbatim to
        #   +Msf::DBManager#report_host+ (e.g. +:workspace+, +:os_name+,
        #   +:mac+).
        # @return [Msf::Reporting::Results::Persisted,
        #          Msf::Reporting::Results::Skipped,
        #          Msf::Reporting::Results::Failed]
        def report_host(address:, **kwargs)
          return Results::Skipped.new(entity_type: :host, reason: :db_inactive) unless db_active?

          ConnectionPool.with_connection do
            begin
              row = @framework.db.report_host(kwargs.merge(host: address))
            rescue StandardError => e
              return Results::Failed.new(entity_type: :host, error: wrap_error(e))
            end

            if row.nil?
              Results::Skipped.new(entity_type: :host, reason: :db_inactive)
            else
              Results::Persisted.new(entity_type: :host, row_id: row.id, row: row, touched: false)
            end
          end
        end

        private

        def db_active?
          @framework &&
            @framework.respond_to?(:db) &&
            @framework.db &&
            @framework.db.respond_to?(:active) &&
            @framework.db.active
        end

        def wrap_error(exception)
          return exception if exception.is_a?(BackendError)

          BackendError.new(exception.message)
        end
      end
    end
  end
end
