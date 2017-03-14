require 'metasploit/framework/credential'

module Metasploit
  module Framework
    # This module provides the namespace for all LoginScanner classes.
    # LoginScanners are the classes that provide functionality for testing
    # authentication against various different protocols and mechanisms.
    module LoginScanner
      require 'metasploit/framework/login_scanner/result'
      require 'metasploit/framework/login_scanner/invalid'

      # Gather a list of LoginScanner classes that can potentially be
      # used for a given `service`, which should usually be an
      # `Mdm::Service` object, but can be anything that responds to
      # #name and #port.
      #
      # @param service [Mdm::Service,#port,#name]
      # @return [Array<LoginScanner::Base>] A collection of LoginScanner
      #   classes that will probably give useful results when run
      #   against `service`.
      def self.classes_for_service(service)

        unless @required
          # Make sure we've required all the scanner classes
          dir = File.expand_path("../login_scanner/", __FILE__)
          Dir.glob(File.join(dir, "*.rb")).each do |f|
            require f if File.file?(f)
          end
          @required = true
        end

        self.constants.map{|sym| const_get(sym)}.select do |const|
          next unless const.kind_of?(Class)

          (
            const.const_defined?(:LIKELY_PORTS) &&
            const.const_get(:LIKELY_PORTS).include?(service.port)
          ) || (
            const.const_defined?(:LIKELY_SERVICE_NAMES) &&
            const.const_get(:LIKELY_SERVICE_NAMES).include?(service.name)
          )
        end
      end

    end
  end
end
