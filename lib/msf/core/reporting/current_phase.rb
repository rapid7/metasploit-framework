# frozen_string_literal: true

module Msf
  module Reporting
    # Thread-local holder for the currently-active
    # +Mdm::ModuleExecutionError#lifecycle_phase+ value. Wired into
    # +Msf::Reporting::Execution.with_phase_setup+ /
    # +.with_phase_cleanup+ so that both +.capture_exception!+ and
    # +.record_failure!+ (the +fail_with+ path, which writes its error
    # row BEFORE the raised exception reaches a +with_phase_*+ rescue)
    # can agree on the phase without needing the exception object to
    # be re-inspected.
    #
    # Symmetric with {Msf::Reporting::CurrentExecution}: per-thread,
    # nested blocks save and restore the previous value on exit
    # (including via exception), and +nil+ means "fall back to the
    # {Msf::Reporting::Execution.phase_for} module-type / execution-kind
    # resolution".
    #
    # @example
    #   Msf::Reporting::CurrentPhase.with(Msf::Reporting::Execution::PHASE_SETUP) do
    #     mod.setup   # fail_with inside setup now records phase='setup'
    #   end
    module CurrentPhase
      THREAD_KEY = :msf_reporting_current_phase
      private_constant :THREAD_KEY

      module_function

      # The currently-active +lifecycle_phase+ string for this thread,
      # or +nil+ when none is set.
      #
      # @return [String, nil]
      def current
        Thread.current[THREAD_KEY]
      end

      # Set the current phase for the duration of the block. The
      # previous value (which may be +nil+) is restored on block exit,
      # including via exception.
      #
      # @param phase [String, Symbol, nil] pass +nil+ to explicitly
      #   clear the override inside the block.
      # @yield with no arguments.
      # @return [Object] the block's return value.
      # @raise [LocalJumpError] when called without a block.
      def with(phase)
        raise LocalJumpError, 'no block given (yield)' unless block_given?

        previous = Thread.current[THREAD_KEY]
        Thread.current[THREAD_KEY] = phase.nil? ? nil : phase.to_s
        begin
          yield
        ensure
          Thread.current[THREAD_KEY] = previous
        end
      end

      # Clear the current-phase slot on the current thread. Primarily
      # useful in tests and in the rare error path where a +with+ block
      # cannot be used.
      def clear
        Thread.current[THREAD_KEY] = nil
      end
    end
  end
end
