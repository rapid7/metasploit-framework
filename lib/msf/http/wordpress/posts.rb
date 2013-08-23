# -*- coding: binary -*-
module Msf::HTTP::Wordpress::Posts

	# Posts a comment as an authenticated user
	#
	# @param comment [String] The comment
	# @param comment_post_id [Integer] The Post ID to post the comment to
	# @param login_cookie [String] The valid login_cookie
	# @return [String] The location of the new comment/post
	def wordpress_post_comment_auth(comment, comment_post_id, login_cookie)
		wordpress_helper_post_comment(comment, comment_post_id, login_cookie, nil, nil, nil)
	end

	# Posts a comment as an unauthenticated user
	#
	# @param comment [String] The comment
	# @param comment_post_id [Integer] The Post ID to post the comment to
	# @param author [String] The author name
	# @param email [String] The author email
	# @param url [String] The author url
	# @return [String] The location of the new comment/post
	def wordpress_post_comment_no_auth(comment, comment_post_id, author, email, url)
		wordpress_helper_post_comment(comment, comment_post_id, nil, author, email, url)
	end

	# Tries to bruteforce a valid post_id
	#
	# @param min_post_id [Integer] The first post_id to bruteforce
	# @param max_post_id [Integer] The last post_id to bruteforce
	# @param login_cookie [String] If set perform the bruteforce as an authenticated user
	# @return [Integer] The post id, nil when nothing found
	def wordpress_get_valid_post_id(min_post_id, max_post_id, login_cookie=nil)
		return nil if min_post_id > max_post_id
		range = Range.new(min_post_id, max_post_id)
		wordpress_helper_get_valid_post_id(range, false, login_cookie)
	end

	# Tries to bruteforce a valid post_id with comments enabled
	#
	# @param min_post_id [Integer] The first post_id to bruteforce
	# @param max_post_id [Integer] The last post_id to bruteforce
	# @param login_cookie [String] If set perform the bruteforce as an authenticated user
	# @return [Integer] The post id, nil when nothing found
	def wordpress_get_valid_post_id_with_comments_enabled(min_post_id, max_post_id, login_cookie=nil)
		return nil if min_post_id > max_post_id
		range = Range.new(min_post_id, max_post_id)
		wordpress_helper_get_valid_post_id(range, true, login_cookie)
	end

	# Checks if the provided post has comments enabled
	#
	# @param post_id [Integer] The post ID to check
	# @param login_cookie [String] If set perform the check as an authenticated user
	# @return [String] the HTTP response body of the post, nil otherwise
	def wordpress_post_comments_enabled?(post_id, login_cookie=nil)
		wordpress_helper_check_post_id(wordpress_url_post(post_id), true, login_cookie)
	end

end
