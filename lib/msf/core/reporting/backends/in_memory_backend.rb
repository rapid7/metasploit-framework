# frozen_string_literal: true

module Msf
  module Reporting
    module Backends
      # Test-only reporting backend.
      #
      # Records every reporting call in declaration order and returns
      # typed +Msf::Reporting::Results::*+ values so module-author specs
      # can assert on what would have been written, without booting
      # PostgreSQL or loading the +metasploit_data_models+ schema.
      class InMemoryBackend
        # @return [Array<Hash>] ordered list of recorded calls. Each
        #   entry has shape:
        #   +{ entity_type:, method:, kwargs: }+. The +kwargs+ hash is
        #   frozen.
        attr_reader :calls

        # Map of public method name → entity_type symbol attributed to
        # the recorded call. Mirrors the table in
        # contracts/reporter-api.md.
        ENTITY_TYPE_BY_METHOD = {
          report_host: :host,
          report_service: :service,
          report_vuln: :vuln,
          report_vuln_attempt: :vuln_attempt,
          report_exploit_attempt: :exploit_attempt,
          report_note: :note,
          report_loot: :loot,
          report_client: :client,
          report_web_site: :web_site,
          report_web_page: :web_page,
          report_web_form: :web_form,
          report_web_vuln: :web_vuln,
          report_session_event: :session_event,
          create_credential: :credential,
          create_credential_login: :credential_login,
          invalidate_login: :login
        }.freeze

        def initialize
          @calls = []
          @next_row_id = 0
          @db_inactive = false
          @failures = Hash.new { |h, k| h[k] = [] }
        end

        # Toggle the simulated DB-inactive state. Subsequent
        # single-entity calls return +Skipped(reason: :db_inactive)+
        # until cleared.
        #
        # @param value [Boolean]
        def db_inactive!(value: true)
          @db_inactive = value
        end

        # Queue a typed error to be returned (inside +Failed+) by the
        # next call to the named method, then consumed.
        #
        # @param method [Symbol] e.g. +:report_host+
        # @param error [Msf::Reporting::Error]
        def fail_next!(method, error)
          @failures[method] << error
        end

        # Reset all recorded calls and failure injections. Useful inside
        # +before(:each)+ blocks when sharing a single backend instance.
        def reset!
          @calls.clear
          @failures.clear
          @next_row_id = 0
          @db_inactive = false
        end

        ENTITY_TYPE_BY_METHOD.each do |method, entity_type|
          define_method(method) do |**kwargs|
            record_single(method, entity_type, kwargs)
          end
        end

        # Compound +report_session+ stub. Records the call and returns
        # a +Compound+ whose steps mirror the documented order. Each
        # inner step is recorded as a single-entity call too, so
        # downstream parity tests can assert on either layer.
        #
        # @return [Msf::Reporting::Results::Compound]
        def report_session(host:, service:, session:, vuln: nil, exploit_attempt: nil, raise_on_failure: true)
          @calls << {
            entity_type: :session,
            method: :report_session,
            kwargs: { host: host, service: service, session: session, vuln: vuln, exploit_attempt: exploit_attempt, raise_on_failure: raise_on_failure }.freeze
          }

          steps = []
          steps << record_single(:report_host, :host, host) if host
          steps << record_single(:report_service, :service, service) if service
          steps << simulated_session_step(session)
          steps << record_single(:report_vuln, :vuln, vuln) if vuln
          steps << record_single(:report_exploit_attempt, :exploit_attempt, exploit_attempt) if exploit_attempt

          overall = if @db_inactive
                      :skipped_db_inactive
                    elsif steps.any?(&:failed?)
                      steps.any?(&:persisted?) ? :partial : :failed
                    else
                      :ok
                    end

          result = Results::Compound.new(steps: steps, overall: overall)

          if raise_on_failure && %i[partial failed].include?(overall)
            raise CompoundError, result
          end

          result
        end

        private

        def record_single(method, entity_type, kwargs)
          frozen_kwargs = (kwargs || {}).dup.freeze
          @calls << { entity_type: entity_type, method: method, kwargs: frozen_kwargs }

          if @db_inactive
            return Results::Skipped.new(entity_type: entity_type, reason: :db_inactive)
          end

          if (queued = @failures[method]) && !queued.empty?
            return Results::Failed.new(entity_type: entity_type, error: queued.shift)
          end

          Results::Persisted.new(entity_type: entity_type, row_id: next_row_id, row: nil, touched: false)
        end

        def simulated_session_step(session)
          @calls << { entity_type: :session, method: :persist_session, kwargs: { session: session }.freeze }
          if @db_inactive
            Results::Skipped.new(entity_type: :session, reason: :db_inactive)
          else
            Results::Persisted.new(entity_type: :session, row_id: next_row_id, row: nil, touched: false)
          end
        end

        def next_row_id
          @next_row_id += 1
        end
      end
    end
  end
end
