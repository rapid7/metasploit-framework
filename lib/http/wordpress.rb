# -*- coding: binary -*-

# This module provides a way of interacting with wordpress installations
module HTTP
	module Wordpress
		require 'http/wordpress/base'
		require 'http/wordpress/helpers'
		require 'http/wordpress/login'
		require 'http/wordpress/posts'
		require 'http/wordpress/uris'
		require 'http/wordpress/users'

		include Msf::Exploit::Remote::HttpClient
		include HTTP::Wordpress::Base
		include HTTP::Wordpress::Helpers
		include HTTP::Wordpress::Login
		include HTTP::Wordpress::Posts
		include HTTP::Wordpress::URIs
		include HTTP::Wordpress::Users

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
