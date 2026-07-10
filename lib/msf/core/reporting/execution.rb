# frozen_string_literal: true

module Msf
  module Reporting
    # Lifecycle helpers that create and finalize +Mdm::ModuleExecution+
    # rows around module runs. Wired into +Msf::Simple::*+ so the row
    # exists for the duration of the run and is the parent association
    # every artifact carries.
    #
    # @example
    #   execution = Msf::Reporting::Execution.start!(
    #     framework: framework,
    #     mod: mod,
    #     originating_interface: 'console'
    #   )
    #   Msf::Reporting::CurrentExecution.with(execution) do
    #     mod.run
    #     Msf::Reporting::Execution.finalize!(execution, terminal_status: 'success')
    #   end
    module Execution
      KIND_RUN = 'run'
      KIND_CHECK = 'check'

      TERMINAL_RUNNING = 'running'
      TERMINAL_SUCCESS = 'success'
      TERMINAL_NEUTRAL = 'neutral'
      TERMINAL_EXPECTED_FAILURE = 'expected_failure'
      TERMINAL_UNHANDLED_EXCEPTION = 'unhandled_exception'

      PHASE_SETUP = 'setup'
      PHASE_CHECK = 'check'
      PHASE_EXPLOIT = 'exploit'
      PHASE_CLEANUP = 'cleanup'
      PHASE_POST = 'post'
      PHASE_RUN = 'run'

      # Cap on the size of a serialized backtrace stored in
      # +Mdm::ModuleExecutionError#backtrace+. PostgreSQL +text+ is
      # unbounded; this is a defensive ceiling so a runaway backtrace
      # never blows up the connection.
      MAX_BACKTRACE_BYTES = 64 * 1024

      # Instance variable used to mark exceptions that have already
      # been written to +module_execution_errors+ so the same exception
      # is not recorded twice when it bubbles through both +fail_with+
      # and the surrounding +handle_exception+ / simple-wrapper rescue.
      # @api private
      RECORDED_EXCEPTION_IVAR = :@_msf_reporting_error_recorded

      # Module-instance ivar set by +Msf::Exploit#handle_exception+
      # whenever it captures an unmapped exception (i.e. anything that
      # is not +Msf::Exploit::Failed+/+Complete+/+OptionValidateError+/
      # +::Interrupt+). +Msf::Simple::Exploit.finalize_exploit_execution+
      # consults it so the parent +Mdm::ModuleExecution+ row records
      # +unhandled_exception+ instead of +expected_failure+ when an
      # exploit raised an exception that the driver swallowed via
      # +handle_exception+.
      # @api private
      UNHANDLED_EXCEPTION_IVAR = :@_msf_reporting_unhandled_exception

      module_function

      # Persist a new +Mdm::ModuleExecution+ row in the +running+ state.
      #
      # @param framework [Msf::Framework] required.
      # @param mod [Msf::Module] required; the module about to run.
      # @param originating_interface [String, Symbol] one of
      #   +Mdm::ModuleExecution::ORIGINATING_INTERFACES+ (e.g. +'console'+,
      #   +'rpc'+, +'mcp'+).
      # @param parent_execution_id [Integer, nil] FK to the parent row
      #   when this execution was spawned from another module.
      # @param kind [String] one of +Mdm::ModuleExecution::KINDS+;
      #   defaults to +'run'+. Pass +'check'+ when wrapping
      #   +check_simple+.
      # @param started_at [Time, nil] override for tests; defaults to
      #   +Time.now.utc+.
      # @return [Mdm::ModuleExecution, nil] +nil+ when no workspace can
      #   be resolved or persistence fails.
      def start!(framework:, mod:, originating_interface:, parent_execution_id: nil, kind: KIND_RUN, started_at: nil)
        workspace = resolve_workspace(framework)
        return nil if workspace.nil?

        attrs = {
          workspace: workspace,
          module_reference_name: module_reference_name_for(mod),
          module_type: module_type_for(mod),
          kind: kind.to_s,
          options_snapshot: capture_options_snapshot(mod),
          originating_interface: originating_interface.to_s,
          originating_user_id: nil,
          originating_token_ref: nil,
          parent_execution_id: parent_execution_id,
          started_at: started_at || Time.now.utc,
          terminal_status: TERMINAL_RUNNING,
          single_entity_failure_count: 0
        }

        Msf::Reporting::ConnectionPool.with_connection do
          ::Mdm::ModuleExecution.create!(attrs)
        end
      rescue StandardError => e
        wlog("Reporting: failed to create ModuleExecution for #{safe_refname(mod)}: #{e.class}: #{e.message}")
        nil
      end

      # Update a previously-started execution with its terminal status
      # and end timestamp.
      #
      # @param execution [Mdm::ModuleExecution, nil] the row returned by
      #   {.start!}. A +nil+ execution is a no-op so that callers can
      #   wrap unconditionally.
      # @param terminal_status [String] one of
      #   +Mdm::ModuleExecution::TERMINAL_STATUSES+ other than +'running'+.
      # @param failure_reason [String, nil] +Msf::Module::Failure+
      #   constant string when applicable.
      # @param failure_message [String, nil] human-readable failure
      #   detail; stored verbatim.
      # @param ended_at [Time, nil] override for tests; defaults to
      #   +Time.now.utc+.
      # @return [Mdm::ModuleExecution, nil] the same execution passed in.
      def finalize!(execution, terminal_status:, failure_reason: nil, failure_message: nil, ended_at: nil)
        return nil if execution.nil?

        Msf::Reporting::ConnectionPool.with_connection do
          execution.update!(
            ended_at: ended_at || Time.now.utc,
            terminal_status: terminal_status.to_s,
            failure_reason: failure_reason,
            failure_message: failure_message
          )
        end
        execution
      rescue StandardError => e
        id = execution.respond_to?(:id) ? execution.id : nil
        wlog("Reporting: failed to finalize ModuleExecution ##{id}: #{e.class}: #{e.message}")
        execution
      end

      # Capture the module's datastore as a string-keyed hash. Persisted
      # verbatim.
      #
      # @param mod [Msf::Module]
      # @return [Hash{String=>Object}, nil]
      def capture_options_snapshot(mod)
        return nil unless mod.respond_to?(:datastore) && mod.datastore

        if mod.datastore.respond_to?(:to_h)
          mod.datastore.to_h
        else
          {}
        end
      rescue StandardError => e
        wlog("Reporting: failed to capture options_snapshot for #{safe_refname(mod)}: #{e.class}: #{e.message}")
        nil
      end

      # Map an +Msf::Exploit::CheckCode+ instance to a terminal_status
      # string.
      #
      # @param check_code [Msf::Exploit::CheckCode, Object, nil]
      # @return [String] one of {TERMINAL_SUCCESS}, {TERMINAL_NEUTRAL}.
      def terminal_status_for_check_code(check_code)
        code = check_code.respond_to?(:code) ? check_code.code : nil
        case code
        when 'vulnerable', 'appears'
          TERMINAL_SUCCESS
        else
          # safe, detected, unknown, unsupported, or anything else
          TERMINAL_NEUTRAL
        end
      end

      # Persist one +Mdm::ModuleExecutionError+ row attached to
      # +execution+. The row captures either an
      # unhandled exception or an explicit +fail_with+-driven failure;
      # +exception+ and +failure_reason+ are independent and may both
      # be supplied.
      #
      # A +nil+ execution or a persistence failure is silently swallowed
      # (with a +wlog+) so the calling module is never destabilized by
      # reporting.
      #
      # @param execution [Mdm::ModuleExecution, nil]
      # @param lifecycle_phase [String, Symbol] one of
      #   +Mdm::ModuleExecutionError::LIFECYCLE_PHASES+; see {phase_for}.
      # @param exception [Exception, nil] originating exception, when any.
      # @param failure_reason [String, nil] +Msf::Module::Failure+
      #   constant string for +fail_with+-driven failures.
      # @param message [String, nil] override for the human-readable
      #   message; defaults to +exception.message+.
      # @param occurred_at [Time, nil] timestamp; defaults to now.
      # @return [Mdm::ModuleExecutionError, nil] the persisted row, or
      #   +nil+ when no row could be written.
      def record_error!(execution, lifecycle_phase:, exception: nil, failure_reason: nil, message: nil, occurred_at: nil)
        return nil if execution.nil?

        attrs = {
          module_execution: execution,
          lifecycle_phase: lifecycle_phase.to_s,
          exception_class: exception&.class&.name,
          message: message || exception&.message,
          backtrace: truncate_backtrace_for_storage(exception&.backtrace),
          failure_reason: failure_reason,
          occurred_at: occurred_at || Time.now.utc
        }

        Msf::Reporting::ConnectionPool.with_connection do
          ::Mdm::ModuleExecutionError.create!(attrs)
        end
      rescue StandardError => e
        id = execution.respond_to?(:id) ? execution.id : nil
        wlog("Reporting: failed to record ModuleExecutionError for execution ##{id}: #{e.class}: #{e.message}")
        nil
      end

      # Capture +exception+ against the currently-running execution,
      # deduplicating so the same exception object is only persisted
      # once even when it bubbles through multiple rescue layers
      # (e.g. +fail_with+ → +handle_exception+ → simple wrapper).
      #
      # @param mod [Msf::Module]
      # @param exception [Exception]
      # @param lifecycle_phase [String, Symbol, nil] override; defaults
      #   to {phase_for}.
      # @param failure_reason [String, nil]
      # @return [Mdm::ModuleExecutionError, nil]
      def capture_exception!(mod, exception, lifecycle_phase: nil, failure_reason: nil)
        return nil if exception.nil?
        return nil if exception_recorded?(exception)

        execution = Msf::Reporting::CurrentExecution.current
        return nil if execution.nil?

        phase = lifecycle_phase || phase_for(mod, execution: execution)
        row = record_error!(
          execution,
          lifecycle_phase: phase,
          exception: exception,
          failure_reason: failure_reason
        )
        mark_exception_recorded(exception)
        row
      end

      # Capture a +fail_with+-driven failure against the currently-running
      # execution. Writes one row with +exception_class: nil+ (per
      # data-model) and the supplied +failure_reason+ /  +message+.
      #
      # @param mod [Msf::Module]
      # @param failure_reason [String, nil] +Msf::Module::Failure+
      #   constant string.
      # @param message [String, nil]
      # @param lifecycle_phase [String, Symbol, nil] override; defaults
      #   to {phase_for}.
      # @return [Mdm::ModuleExecutionError, nil]
      def record_failure!(mod, failure_reason: nil, message: nil, lifecycle_phase: nil)
        execution = Msf::Reporting::CurrentExecution.current
        return nil if execution.nil?

        phase = lifecycle_phase || phase_for(mod, execution: execution)
        record_error!(
          execution,
          lifecycle_phase: phase,
          failure_reason: failure_reason,
          message: message
        )
      end

      # Derive the +lifecycle_phase+ to attribute an error to. Resolution
      # order:
      #
      # 1. {PHASE_CHECK} when the active execution's +kind+ is +check+.
      #    This covers both the standalone +check_simple+ entry point
      #    and +Msf::Exploit::Remote::AutoCheck+, which spawns a child
      #    +Mdm::ModuleExecution+ row with +kind: 'check'+ around its
      #    embedded +check+ call.
      # 2. The module-type fallback: +exploit+ → {PHASE_EXPLOIT};
      #    +post+ → {PHASE_POST}; everything else → {PHASE_RUN}.
      #
      # @param mod [Msf::Module]
      # @param execution [Mdm::ModuleExecution, nil]
      # @return [String]
      def phase_for(mod, execution: nil)
        kind = execution.respond_to?(:kind) ? execution.kind.to_s : nil
        return PHASE_CHECK if kind == KIND_CHECK

        case module_type_for(mod)
        when 'exploit'
          PHASE_EXPLOIT
        when 'post'
          PHASE_POST
        else
          PHASE_RUN
        end
      end

      # Run +block+ around a +mod.cleanup+ invocation and capture any
      # exception it raises against the currently-active
      # +Mdm::ModuleExecution+ with +lifecycle_phase: 'cleanup'+, then
      # re-raise. Used at the +mod.cleanup+ boundary in the simple
      # wrappers so a failure inside cleanup lands in
      # +module_execution_errors+ with the correct phase, even though
      # the surrounding {phase_for} would otherwise resolve to the
      # module-type fallback (e.g. +'exploit'+ or +'post'+).
      #
      # Deduplicates against the recorded-exception ivar, so an outer
      # rescue chain calling {.capture_exception!} on the same
      # exception object will not write a second row.
      #
      # No-op (other than yielding) when no execution is active.
      #
      # @param mod [Msf::Module]
      # @yield with no arguments.
      # @return [Object] the block's return value.
      def with_phase_cleanup(mod)
        yield
      rescue ::Exception => e # rubocop:disable Lint/RescueException -- attribute setup/cleanup failures (including Interrupt) before the surrounding wrapper rescues
        capture_exception!(mod, e, lifecycle_phase: Msf::Reporting::Execution::PHASE_CLEANUP)
        raise
      end

      # Run +block+ around a +mod.setup+ invocation and capture any
      # exception it raises against the currently-active
      # +Mdm::ModuleExecution+ with +lifecycle_phase: 'setup'+, then
      # re-raise. Used at the +mod.setup+ boundary in the simple
      # wrappers so a failure inside setup lands in
      # +module_execution_errors+ with the correct phase, even though
      # the surrounding {phase_for} would otherwise resolve to the
      # module-type fallback (e.g. +'exploit'+ or +'post'+).
      #
      # Deduplicates against the recorded-exception ivar, so an outer
      # rescue chain calling {.capture_exception!} on the same
      # exception object will not write a second row.
      #
      # No-op (other than yielding) when no execution is active.
      #
      # @param mod [Msf::Module]
      # @yield with no arguments.
      # @return [Object] the block's return value.
      def with_phase_setup(mod)
        yield
      rescue ::Exception => e # rubocop:disable Lint/RescueException -- attribute setup/cleanup failures (including Interrupt) before the surrounding wrapper rescues
        capture_exception!(mod, e, lifecycle_phase: Msf::Reporting::Execution::PHASE_SETUP)
        raise
      end

      # Serialize a backtrace for storage in
      # +Mdm::ModuleExecutionError#backtrace+, capped at +max_bytes+ to
      # protect against pathological cases.
      #
      # @param backtrace [Array<String>, String, nil]
      # @param max_bytes [Integer]
      # @return [String, nil]
      def truncate_backtrace_for_storage(backtrace, max_bytes: MAX_BACKTRACE_BYTES)
        return nil if backtrace.nil?

        joined = backtrace.is_a?(Array) ? backtrace.join("\n") : backtrace.to_s
        return nil if joined.empty?
        return joined if joined.bytesize <= max_bytes

        joined.byteslice(0, max_bytes)
      end

      # @api private
      def exception_recorded?(exception)
        exception.instance_variable_defined?(RECORDED_EXCEPTION_IVAR) &&
          exception.instance_variable_get(RECORDED_EXCEPTION_IVAR)
      rescue StandardError
        false
      end

      # @api private
      def mark_exception_recorded(exception)
        exception.instance_variable_set(RECORDED_EXCEPTION_IVAR, true)
      rescue StandardError
        nil
      end

      # @api private
      def mark_module_unhandled_exception(mod)
        mod.instance_variable_set(UNHANDLED_EXCEPTION_IVAR, true)
      rescue StandardError
        nil
      end

      # Clear the unhandled-exception flag on +mod+. Called at the
      # start of each simple wrapper so the flag never leaks across
      # consecutive runs that reuse the same module instance (e.g.
      # +check_simple+ and +run_simple+ on +Auxiliary+ / +Post+ do
      # not allocate a +replicant+ first).
      # @api private
      def clear_module_unhandled_exception(mod)
        return if mod.nil?

        if mod.instance_variable_defined?(UNHANDLED_EXCEPTION_IVAR)
          mod.remove_instance_variable(UNHANDLED_EXCEPTION_IVAR)
        end
      rescue StandardError
        nil
      end

      # @api private
      def module_unhandled_exception?(mod)
        return false if mod.nil?

        mod.instance_variable_defined?(UNHANDLED_EXCEPTION_IVAR) &&
          mod.instance_variable_get(UNHANDLED_EXCEPTION_IVAR)
      rescue StandardError
        false
      end

      # @api private
      def resolve_workspace(framework)
        return nil if framework.nil?
        return nil unless framework.respond_to?(:db) && framework.db
        return nil unless framework.db.respond_to?(:active) && framework.db.active
        return nil unless framework.db.respond_to?(:workspace)

        framework.db.workspace
      rescue StandardError
        nil
      end

      # @api private
      def module_reference_name_for(mod)
        if mod.respond_to?(:fullname) && mod.fullname
          mod.fullname
        elsif mod.respond_to?(:refname) && mod.refname
          mod.refname
        else
          mod.class.name.to_s
        end
      end

      # @api private
      def module_type_for(mod)
        mod.respond_to?(:type) ? mod.type.to_s : ''
      end

      # @api private
      def safe_refname(mod)
        mod.respond_to?(:refname) ? mod.refname : mod.class.name
      rescue StandardError
        '<unknown module>'
      end
    end
  end
end
