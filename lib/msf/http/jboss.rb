# -*- coding: binary -*-

# This module provides a way of interacting with JBoss installations
module Msf
  module HTTP
    module JBoss
      require 'msf/http/jboss/base'
      require 'msf/http/jboss/bean_shell_scripts'
      require 'msf/http/jboss/bean_shell'

      include Msf::Exploit::Remote::HttpClient
      include Msf::HTTP::JBoss::Base
      include Msf::HTTP::JBoss::BeanShellScripts
      include Msf::HTTP::JBoss::BeanShell

      def initialize(info = {})     
        super

        register_options(
          [
            OptString.new('TARGETURI', [true,  'The URI path of the JMX console', '/jmx-console']),
            OptEnum.new('VERB',        [true,  'HTTP Method to use (for CVE-2010-0738)', 'POST', ['GET', 'POST', 'HEAD']]),
            OptString.new('PACKAGE',   [false, 'The package containing the BSHDeployer service'])
          ], self.class)
      end

    end
  end
end
