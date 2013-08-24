# -*- coding: binary -*-
module Msf::HTTP::Wordpress::Login

	# performs a wordpress login
	#
	# @param user [String] Username
	# @param pass [String] Password
	# @return [String,nil] the session cookie on successful login, nil otherwise
	def wordpress_login(user, pass)
		redirect = "#{target_uri}#{Rex::Text.rand_text_alpha(8)}"
		res = send_request_cgi({
				'method' => 'POST',
				'uri' => wordpress_url_login,
				'vars_post' => wordpress_helper_login_post_data(user, pass, redirect)
		})

		if res and (res.code == 301 or res.code == 302) and res.headers['Location'] == redirect
			match = res.get_cookies.match(/(wordpress(?:_sec)?_logged_in_[^=]+=[^;]+);/i)
			# return wordpress login cookie
			return match[0] if match
		end
		return nil
	end

end
