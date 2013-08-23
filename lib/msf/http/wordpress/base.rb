# -*- coding: binary -*-

module Msf::HTTP::Wordpress::Base

	# Checks if the site is online and running wordpress
	#
	# @return [Boolean] Returns true if the site is online and running wordpress
	def wordpress_and_online?
		begin
			res = send_request_cgi({
					'method' => 'GET',
					'uri' => normalize_uri(target_uri)
			}, 20)
			return true if res and
					res.code == 200 and
					(
						res.body =~ /["'][^"']*\/wp-content\/[^"']*["']/i or
						res.body =~ /<link rel=["']wlwmanifest["'].*href=["'].*\/wp-includes\/wlwmanifest\.xml["'] \/>/i or
						res.body =~ /<link rel=["']pingback["'].*href=["'].*\/xmlrpc\.php["'] \/>/i
					)
			return false
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			print_error("Error connecting to #{target_uri}")
			return false
		end
	end
end
