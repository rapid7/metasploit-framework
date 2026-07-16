# frozen_string_literal: true

module Msf
  module Reporting
    # Thin façade over +ActiveRecord::Base.connection_pool#with_connection+.
    # Every reporter backend that touches the DB MUST go through this
    # helper so the framework owns a single, audited connection-checkout
    # policy.
    #
    # ActiveRecord's +with_connection+ already guarantees release of the
    # checked-out connection on:
    # * normal block exit
    # * +return+ / +next+ / +break+ from inside the block
    # * any exception raised from inside the block (including
    #   +Thread#raise+)
    #
    # We layer no additional +ensure+ semantics on top — that would risk
    # double-releasing the connection. The value of this helper is the
    # single, well-named call site so static analysis and audit work
    # can find every connection checkout in the reporting subsystem.
    #
    # @example
    #   Msf::Reporting::ConnectionPool.with_connection do
    #     Mdm::Host.find_or_create_by!(...)
    #   end
    module ConnectionPool
      module_function

      # Yield while holding a checked-out AR connection. When ActiveRecord
      # is not loaded (e.g. the in-memory test backend) the block is run
      # directly so callers stay transport-agnostic.
      #
      # @yield with no arguments.
      # @return [Object] the block's return value.
      # @raise [LocalJumpError] when called without a block.
      def with_connection(&block)
        raise LocalJumpError, 'no block given (yield)' unless block

        if defined?(::ApplicationRecord) && ::ApplicationRecord.respond_to?(:connection_pool)
          ::ApplicationRecord.connection_pool.with_connection(&block)
        else
          block.call
        end
      end
    end
  end
end
