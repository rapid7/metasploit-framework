# -*- coding: binary -*-
module Msf::HTTP::Wordpress::Users

	# Checks if the given user exists
	#
	# @param user [String] Username
	# @return [Boolean] true if the user exists
	def wordpress_user_exists?(user)
		res = send_request_cgi({
				'method' => 'POST',
				'uri' => wordpress_uri_login,
				'vars_post' => wordpress_helper_login_post_data(user, rand_text_alpha(6))
		})

		return true if res and res.code == 200 and
				(res.body.to_s =~ /Incorrect password/ or
						res.body.to_s =~ /document\.getElementById\('user_pass'\)/)

		return false
	end

	# Checks if the given userid exists
	#
	# @param user_id [Integer] user_id
	# @return [String] the Username if it exists, nil otherwise
	def wordpress_userid_exists?(user_id)
		url = wordpress_url_author(user_id)
		res = send_request_cgi({
				'method' => 'GET',
				'uri' => url
		})

		if res and res.code == 301
			uri = wordpress_helper_parse_location_header(res)
			return nil unless uri
			# try to extract username from location
			if uri.to_s =~ /\/author\/([^\/\b]+)\/?/i
				return $1
			end
			uri = "#{uri.path}?#{uri.query}"
			res = send_request_cgi({
					'method' => 'GET',
					'uri' => uri
			})
		end

		if res.nil?
			print_error("#{target_uri} - Error getting response.")
			return nil
		elsif res.code == 200 and
				(res.body =~ /href="http[s]*:\/\/.*\/\?*author.+title="([[:print:]]+)" /i or
						res.body =~ /<body class="archive author author-(?:[^\s]+) author-(?:\d+)/i)
			return $1
		end
	end

end
