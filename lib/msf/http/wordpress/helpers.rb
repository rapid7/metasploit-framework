# -*- coding: binary -*-
module Msf::HTTP::Wordpress::Helpers

	# Helper methods are private and should not be called by modules
	private

	# Returns the POST data for a Wordpress login request
	#
	# @param user [String] Username
	# @param pass [String] Password
	# @param redirect URL [String] to redirect after successful login
	# @return [Hash] The post data for vars_post Parameter
	def wordpress_helper_login_post_data(user, pass, redirect=nil)
		post_data = {
				'log' => user.to_s,
				'pwd' => pass.to_s,
				'redirect_to' => redirect.to_s,
				'wp-submit' => 'Login'
		}
		post_data
	end

	# Helper method to post a comment to Wordpress
	#
	# @param comment [String] The comment
	# @param comment_post_id [Integer] The Post ID to post the comment to
	# @param login_cookie [String] The valid login_cookie
	# @param author [String] The author name
	# @param email [String] The author email
	# @param url [String] The author url
	# @return [String,nil] The location of the new comment/post, nil on error
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
		if res and (res.code == 301 or res.code == 302) and res.headers['Location']
			return wordpress_helper_parse_location_header(res)
		else
			message = "#{peer} - Post comment failed."
			message << " Status Code: #{res.code}" if res
			print_error(message)
			return nil
		end
	end

	# Helper method for bruteforcing a valid post id
	#
	# @param range [Range] The Range of post_ids to bruteforce
	# @param comments_enabled [Boolean] If true try to find a post id with comments enabled, otherwise return the first found
	# @param login_cookie [String] A valid login cookie to perform the bruteforce as an authenticated user
	# @return [Integer,nil] The post id, nil when nothing found
	def wordpress_helper_bruteforce_valid_post_id(range, comments_enabled=false, login_cookie=nil)
		range.each { |id|
			vprint_status("#{peer} - Checking POST ID #{id}...") if (id % 100) == 0
			body = wordpress_helper_check_post_id(wordpress_url_post(id), comments_enabled, login_cookie)
			return id if body
		}
		# no post found
		return nil
	end

	# Helper method to check if a post is valid an has comments enabled
	#
	# @param uri [String] the Post URI Path
	# @param comments_enabled [Boolean] Check if comments are enabled on this post
	# @param login_cookie [String] A valid login cookie to perform the check as an authenticated user
	# @return [String,nil] the HTTP response body of the post, nil otherwise
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
			path = wordpress_helper_parse_location_header(res)
			return wordpress_helper_check_post_id(path, comments_enabled, login_cookie)
		end
		return nil
	end

	# Helper method parse a Location header and returns only the path and query. Returns nil on error
	#
	# @param res [Rex::Proto::Http::Response] The HTTP response
	# @return [String,nil] the path and query, nil on error
	def wordpress_helper_parse_location_header(res)
		return nil unless res and (res.code == 301 or res.code == 302) and res.headers['Location']

		location = res.headers['Location']
		path_from_uri(location)
	end

end
