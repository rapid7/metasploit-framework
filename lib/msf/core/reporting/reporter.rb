# frozen_string_literal: true

module Msf
  module Reporting
    # Public reporter facade exposed to module authors as
    # +framework.report+. This class is the single entry point for
    # every reporting call; the actual persistence work is delegated to
    # one of the backends in +Msf::Reporting::Backends::*+ resolved at
    # construction time from +framework.db.driver+.
    #
    # Single-entity methods that have not yet been migrated to a
    # concrete backend return +Skipped(reason: :not_implemented)+.
    class Reporter
      # Backend driver enum. Drivers added by future features MUST be
      # registered here before the reporter will load them.
      KNOWN_DRIVERS = %i[db_manager http in_memory].freeze

      # Maps the legacy +framework.db.driver+ values (which today are
      # strings such as +'postgresql'+ and +'http'+) onto the reporter's
      # driver enum. Symbols already in +KNOWN_DRIVERS+ pass through
      # untouched.
      DRIVER_ALIASES = {
        'postgresql' => :db_manager,
        :postgresql => :db_manager,
        'http' => :http,
        'in_memory' => :in_memory
      }.freeze

      # @return [Msf::Framework, nil]
      attr_reader :framework

      # @return [Mdm::Workspace, Object, nil]
      attr_reader :workspace

      # @return [Symbol] one of +KNOWN_DRIVERS+.
      attr_reader :driver

      # @return [Object] the resolved backend instance (an instance of
      #   one of +Msf::Reporting::Backends::*+, or +nil+ for drivers
      #   whose backend has not yet been implemented — currently
      #   +:http+).
      attr_reader :backend

      # @param framework [Msf::Framework, nil] host framework.
      # @param workspace [Mdm::Workspace, Object, nil] active workspace.
      # @param driver [Symbol, String, nil] explicit backend selector;
      #   defaults to +framework.db.driver+ when +framework+ is given,
      #   then to +:in_memory+.
      # @param backend [Object, nil] preconstructed backend instance,
      #   primarily used by tests to inject a fake.
      def initialize(framework: nil, workspace: nil, driver: nil, backend: nil)
        @framework = framework
        @workspace = workspace
        @driver = resolve_driver(driver)
        @backend = backend || build_backend
      end

      # @return [Mdm::ModuleExecution, nil] the execution row tied to the
      #   current thread.
      def current_execution
        nil
      end

      # @return [Msf::Reporting::Results::Persisted,
      #          Msf::Reporting::Results::Skipped,
      #          Msf::Reporting::Results::Failed]
      def report_host(**kwargs)
        return not_implemented(:host) if @backend.nil?

        @backend.report_host(**kwargs)
      end

      # @return [Msf::Reporting::Results::Skipped] stub.
      def report_service(**_kwargs)
        not_implemented(:service)
      end

      # @return [Msf::Reporting::Results::Skipped] stub.
      def report_vuln(**_kwargs)
        not_implemented(:vuln)
      end

      # @return [Msf::Reporting::Results::Skipped] stub.
      def report_note(**_kwargs)
        not_implemented(:note)
      end

      # @return [Msf::Reporting::Results::Skipped] stub.
      def report_loot(**_kwargs)
        not_implemented(:loot)
      end

      # @return [Msf::Reporting::Results::Compound] stub returning a
      #   +:skipped_db_inactive+ compound with no steps.
      def report_session(**_kwargs)
        Results::Compound.new(steps: [], overall: :skipped_db_inactive)
      end

      private

      def resolve_driver(explicit)
        candidate = explicit
        if candidate.nil? && @framework && @framework.respond_to?(:db) && @framework.db.respond_to?(:driver)
          candidate = @framework.db.driver
        end
        candidate = DRIVER_ALIASES.fetch(candidate, candidate) if candidate
        candidate ||= :in_memory
        candidate = candidate.to_sym if candidate.is_a?(String)

        unless KNOWN_DRIVERS.include?(candidate)
          raise Error, "unknown reporting driver #{candidate.inspect}; expected one of #{KNOWN_DRIVERS.inspect}"
        end

        candidate
      end

      def build_backend
        case @driver
        when :db_manager
          Backends::DbManagerBackend.new(framework: @framework)
        when :in_memory
          Backends::InMemoryBackend.new
        when :http
          # No remote backend is wired up yet; the reporter falls through
          # to +Skipped(:not_implemented)+ for this driver.
          nil
        end
      end

      def not_implemented(entity_type)
        Results::Skipped.new(entity_type: entity_type, reason: :not_implemented)
      end
    end
  end
end
