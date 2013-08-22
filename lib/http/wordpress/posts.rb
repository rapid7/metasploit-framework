# -*- coding: binary -*-
module HTTP::Wordpress::Posts

	# Posts a comment as an authenticated user
	#
	# @param comment The comment
	# @param comment_post_id The Post ID to post the comment to
	# @param login_cookie The valid login_cookie
	# @return [String] The location of the new comment/post
	def wordpress_post_comment_auth(comment, comment_post_id, login_cookie)
		wordpress_helper_post_comment(comment, comment_post_id, login_cookie, nil, nil, nil)
	end

	# Posts a comment as an unauthenticated user
	#
	# @param comment The comment
	# @param comment_post_id The Post ID to post the comment to
	# @param author The author name
	# @param email The author email
	# @param url The author url
	# @return [String] The location of the new comment/post
	def wordpress_post_comment_no_auth(comment, comment_post_id, author, email, url)
		wordpress_helper_post_comment(comment, comment_post_id, nil, author, email, url)
	end

	# Tries to bruteforce a valid post_id
	#
	# @param login_cookie If set perform the bruteforce as an authenticated user
	# @return [Integer] The post id, nil when nothing found
	def wordpress_get_valid_post_id(login_cookie=nil)
		wordpress_helper_get_valid_post_id(false, login_cookie)
	end

	# Tries to bruteforce a valid post_id with comments enabled
	#
	# @param login_cookie If set perform the bruteforce as an authenticated user
	# @return [Integer] The post id, nil when nothing found
	def wordpress_get_valid_post_id_with_comments_enabled(login_cookie=nil)
		wordpress_helper_get_valid_post_id(true, login_cookie)
	end

	# Checks if the provided post has comments enabled
	#
	# @param post_id The post ID to check
	# @param login_cookie If set perform the check as an authenticated user
	# @return [String] the HTTP response body of the post, nil otherwise
	def wordpress_post_comments_enabled?(post_id, login_cookie=nil)
		wordpress_helper_check_post_id(wordpress_url_post(post_id), true, login_cookie)
	end

end
