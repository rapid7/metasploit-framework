# frozen_string_literal: true

module Msf
  module Reporting
    # Thread-local holder for the currently-executing
    # +Mdm::ModuleExecution+ row. Wired into +Msf::Simple::*+ so that
    # writers can stamp +module_execution_id+ onto every artifact a
    # module produces or touches.
    #
    # The holder is per-thread so that two modules running in parallel
    # background jobs each see their own execution. Nested blocks save
    # and restore the previous value, so a child module invoked from
    # inside a parent module's execution context correctly observes the
    # child for the duration of the inner block and the parent
    # afterwards.
    #
    # @example
    #   execution = Msf::Reporting::Execution.start!(framework:, mod:, originating_ui: 'console')
    #   Msf::Reporting::CurrentExecution.with(execution) do
    #     mod.run
    #   end
    module CurrentExecution
      THREAD_KEY = :msf_reporting_current_execution
      private_constant :THREAD_KEY

      module_function

      # The currently-active +Mdm::ModuleExecution+ for this thread, or
      # +nil+ when none is set.
      #
      # @return [Object, nil]
      def current
        Thread.current[THREAD_KEY]
      end

      # @return [Integer, nil] the +id+ of {#current}, or +nil+.
      def id
        execution = current
        execution&.id if execution.respond_to?(:id)
      end

      # Set the current execution for the duration of the block. The
      # previous value (which may be +nil+) is restored on block exit,
      # including via exception.
      #
      # @param execution [Object] the execution row, or any object that
      #   responds to +#id+. Pass +nil+ to explicitly clear inside the
      #   block.
      # @yield with no arguments.
      # @return [Object] the block's return value.
      # @raise [LocalJumpError] when called without a block.
      def with(execution)
        raise LocalJumpError, 'no block given (yield)' unless block_given?

        previous = Thread.current[THREAD_KEY]
        Thread.current[THREAD_KEY] = execution
        begin
          yield
        ensure
          Thread.current[THREAD_KEY] = previous
        end
      end

      # Clear the current-execution slot on the current thread. Primarily
      # useful in tests and in the rare error path where a +with+ block
      # cannot be used.
      def clear
        Thread.current[THREAD_KEY] = nil
      end
    end
  end
end
