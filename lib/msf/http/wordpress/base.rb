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
			if res and res.code == 200
				if res.body =~ /["'][^"']*\/wp-content\/[^"']*["']/i or
						res.body =~ /<link rel=["']wlwmanifest["'].*href=["'].*\/wp-includes\/wlwmanifest\.xml["'] \/>/i or
						res.body =~ /<link rel=["']pingback["'].*href=["'].*\/xmlrpc\.php["'] \/>/i
					return true
				else
					return false
				end
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
			print_error("Error connecting to #{target_uri}")
			return false
		end

		return false
	end

end
