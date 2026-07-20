# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      # Detects direct access to datastore['SRVHOST'] and recommends using the srvhost method instead.
      #
      # The srvhost method provides a cleaner API for accessing the SRVHOST value from the datastore.
      #
      # @example
      #   # bad
      #   datastore['SRVHOST']
      #   datastore["SRVHOST"]
      #
      #   # good
      #   srvhost
      class DatastoreSrvhostUsage < Base
        extend AutoCorrector

        MSG = 'Use the `srvhost` method instead of directly accessing `datastore[\'SRVHOST\']`.'

        # @!method datastore_srvhost_access?(node)
        def_node_matcher :datastore_srvhost_access?, <<~PATTERN
          (send
            (send nil? :datastore) :[]
            (str {"SRVHOST"}))
        PATTERN

        # Called for every method call in the code
        # Checks if it's a datastore['SRVHOST'] access and registers an offense if so
        # @param node [RuboCop::AST::SendNode] The method call node being checked
        def on_send(node)
          return unless datastore_srvhost_access?(node)

          add_offense(node, message: MSG) do |corrector|
            corrector.replace(node, 'srvhost')
          end
        end
      end
    end
  end
end
