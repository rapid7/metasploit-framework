# -*- coding: binary -*-

# This module provides a way of interacting with JBoss installations
module Msf
  module HTTP
    module JBoss
      require 'msf/http/jboss/base'
      require 'msf/http/jboss/bsh'

      include Msf::HTTP::JBoss::Base
      include Msf::HTTP::JBoss::BSH

      def initialize(info = {})
        super
      end
    end
  end
end
