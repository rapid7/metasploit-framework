# -*- coding: binary -*-

module Msf
  class Auxiliary
    ###
    #
    # This module provides a base configure scanner method for binding common datastore options to the login scanners
    #
    ###
    module LoginScanner
      #
      # Converts datastore options into configuration parameters for the
      # Msf::Auxiliary::LoginScanner. Any parameters passed into
      # this method will override the defaults.
      #
      def configure_login_scanner(conf)
        {
          host: datastore['RHOST'],
          port: datastore['RPORT'],
          proxies: datastore['Proxies'],
          stop_on_success: datastore['STOP_ON_SUCCESS'],
          bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
          framework: framework,
          framework_module: self,
          local_port: datastore['CPORT'],
          local_host: datastore['CHOST'],
        }.merge(conf)
      end
    end
  end
end
