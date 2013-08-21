# -*- coding: binary -*-
module HTTP
	module Wordpress
		require 'http/wordpress/wordpress_base'
		require 'http/wordpress/wordpress_helpers'
		require 'http/wordpress/wordpress_login'
		require 'http/wordpress/wordpress_posts'
		require 'http/wordpress/wordpress_uris'
		require 'http/wordpress/wordpress_users'

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
