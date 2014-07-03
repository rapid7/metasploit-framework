require 'metasploit/framework/credential'

module Metasploit
  module Framework
    # This module provides the namespace for all LoginScanner classes.
    # LoginScanners are the classes that provide functionality for testing
    # authentication against various different protocols and mechanisms.
    module LoginScanner
      # Make sure Base is loaded before any of the others
      require 'metasploit/framework/login_scanner/base'

      dir = File.expand_path("../login_scanner/", __FILE__)
      Dir.entries(dir).each do |f|
        f = File.join(dir, f)
        require f if File.file?(f)
      end

      def self.classes_for_service(service)
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
