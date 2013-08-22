# -*- coding: binary -*-
module Msf::HTTP::Wordpress::Helpers

	# Returns the POST data for a Wordpress login request
	#
	# @param user Usernam
	# @param pass Password
	# @param redirect URL to redirect after successful login
	# @return [String] The post data
	def wordpress_helper_login_post_data(user, pass, redirect=nil)
		post_data = "log=#{Rex::Text.uri_encode(user.to_s)}"
		post_data << "&pwd=#{Rex::Text.uri_encode(pass.to_s)}"
		post_data << "&redirect_to=#{Rex::Text.uri_encode(redirect.to_s)}"
		post_data << '&wp-submit=Login'
		post_data
	end

	# Helper method to post a comment to Wordpress
	#
	# @param comment The comment
	# @param comment_post_id The Post ID to post the comment to
	# @param login_cookie The valid login_cookie
	# @param author The author name
	# @param email The author email
	# @param url The author url
	# @return [String] The location of the new comment/post
	def wordpress_helper_post_comment(comment, comment_post_id, login_cookie, author, email, url)
		vars_post = {
				'comment' => comment,
				'submit' => 'Post+Comment',
				'comment_post_ID' => comment_post_id.to_s,
				'comment_parent' => '0'
		}
		vars_post.merge!({
				'author' => author,
				'email' => email,
				'url' => url,
		}) unless login_cookie

		options = {
				'uri' => normalize_uri(target_uri.path, 'wp-comments-post.php'),
				'method' => 'POST'
		}
		options.merge!({'vars_post' => vars_post})
		options.merge!({'cookie' => login_cookie}) if login_cookie
		res = send_request_cgi(options)
		if res and res.code == 302
			location = URI(res.headers['Location'])
			return location
		else
			return nil
		end
	end

	# Helper method for bruteforcing a valid post id
	#
	# @param comments_enabled If true try to find a post id with comments enabled, otherwise return the first found
	# @param login_cookie A valid login cookie to perform the bruteforce as an authenticated user
	# @return [Integer] The post id, nil when nothing found
	def wordpress_helper_get_valid_post_id(comments_enabled=false, login_cookie=nil)
		(1..1000).each { |id|
			vprint_status("#{rhost}:#{rport} - Checking POST ID #{id}...") if (id % 100) == 0
			body = wordpress_helper_check_post_id(wordpress_url_post(id), comments_enabled, login_cookie)
			return id if body
		}
		# no post found
		return nil
	end

	# Helper method to check if a post is valid an has comments enabled
	#
	# @param uri the Post URI
	# @param comments_enabled Check if comments are enabled on this post
	# @param login_cookie A valid login cookie to perform the check as an authenticated user
	# @return [String] the HTTP response body of the post, nil otherwise
	def wordpress_helper_check_post_id(uri, comments_enabled=false, login_cookie=nil)
		options = {
				'method' => 'GET',
				'uri' => uri
		}
		options.merge!({'cookie' => login_cookie}) if login_cookie
		res = send_request_cgi(options)
		# post exists
		if res and res.code == 200
			# also check if comments are enabled
			if comments_enabled
				if res.body =~ /form.*action.*wp-comments-post\.php/
					return res.body
				else
					return nil
				end
				# valid post found, not checking for comments
			else
				return res.body
			end
		elsif res and (res.code == 301 or res.code == 302) and res.headers['Location']
			location = URI(res.headers['Location'])
			uri = location.path
			uri << "?#{location.query}" unless location.query.nil? or location.query.empty?
			return wordpress_helper_check_post_id(uri, comments_enabled, login_cookie)
		end
		return nil
	end
end
