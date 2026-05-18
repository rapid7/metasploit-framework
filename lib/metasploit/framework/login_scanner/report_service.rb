# frozen_string_literal: true

module Metasploit
  module Framework
    module LoginScanner
      # This module provides automatic service reporting for login scanners.
      # When included in a login scanner class, it overrides `check_setup` to
      # automatically call `report_service` with the scanner's `service_details`
      # when the setup check succeeds (i.e. when `super` returns `false`).
      #
      # Each scanner should override `service_details` to merge in its specific
      # service metadata (name, parents, resource, etc.).
      #
      module ReportService
        # Overrides the base `check_setup` to automatically report the service
        # when the scanner determines the target is valid.
        #
        # @return [false] if setup succeeded (no errors)
        # @return [String] a human-readable error message if setup failed
        def check_setup
          result = super
          if result == false
            report_service(service_details)
          end
          result
        end
      end
    end
  end
end
