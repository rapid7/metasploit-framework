# -*- coding: binary -*-
module Msf
  module RPC
    class Health

      # Returns whether the framework object is currently healthy and ready to accept
      # requests
      #
      # @return [Hash]
      #
      def self.check(framework)
        # A couple of rudimentary checks to ensure that nothing breaks when interacting
        # with framework object
        is_healthy = (
          !framework.version.to_s.empty? &&
          # Ensure that the db method can be invoked and returns a truthy value as
          # the rpc clients interact with framework's database object which raises can
          # raise an exception
          framework.db
        )

        unless is_healthy
          return { status: 'DOWN' }
        end

        { status: 'UP' }
      rescue => e
        elog('Health status failing', error: e)

        { status: 'DOWN' }
      end

    end
  end
end
