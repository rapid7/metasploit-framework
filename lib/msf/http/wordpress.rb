# -*- coding: binary -*-

# This module provides a way of interacting with wordpress installations
module Msf
  module HTTP
    module Wordpress
      require 'msf/http/wordpress/base'
      require 'msf/http/wordpress/helpers'
      require 'msf/http/wordpress/login'
      require 'msf/http/wordpress/posts'
      require 'msf/http/wordpress/uris'
      require 'msf/http/wordpress/users'
      require 'msf/http/wordpress/version'

      include Msf::Exploit::Remote::HttpClient
      include Msf::HTTP::Wordpress::Base
      include Msf::HTTP::Wordpress::Helpers
      include Msf::HTTP::Wordpress::Login
      include Msf::HTTP::Wordpress::Posts
      include Msf::HTTP::Wordpress::URIs
      include Msf::HTTP::Wordpress::Users
      include Msf::HTTP::Wordpress::Version

      def initialize(info = {})
        super

        register_options(
            [
                Msf::OptString.new('TARGETURI', [true, 'The base path to the wordpress application', '/']),
            ], HTTP::Wordpress
        )
      end
    end
  end
end
