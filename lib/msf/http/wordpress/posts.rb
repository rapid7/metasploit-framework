# -*- coding: binary -*-
module Msf::HTTP::Wordpress::Posts

	# Posts a comment as an authenticated user
	#
	# @param comment [String] The comment
	# @param comment_post_id [Integer] The Post ID to post the comment to
	# @param login_cookie [String] The valid login_cookie
	# @return [String,nil] The location of the new comment/post, nil on error
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
	# @return [String,nil] The location of the new comment/post, nil on error
	def wordpress_post_comment_no_auth(comment, comment_post_id, author, email, url)
		wordpress_helper_post_comment(comment, comment_post_id, nil, author, email, url)
	end

	# Wordpress shows moderated comments to the unauthenticated Posting user
	# Users are identified by their cookie
	#
	# @param author [String] The author name used to post the anonymous comment
	# @param email [String] The author email used to post the anonymous comment
	# @param url [String] The author url used to post the anonymous comment
	# @return [String] The cookie string that can be used to see moderated comments
	def wordpress_get_unauth_comment_cookies(author, email, url)
		scheme = ssl ? 'https' : 'http'
		port = (rport == 80 or rport == 443) ? '' : rport
		# siteurl does not contain last slash
		path = target_uri.to_s.sub(/\/$/, '')
		siteurl = "#{scheme}://#{rhost}#{port}#{path}"
		site_hash = Rex::Text.md5(siteurl)
		cookie = "comment_author_#{site_hash}=#{author}; "
		cookie << "comment_author_email_#{site_hash}=#{email}; "
		cookie << "comment_author_url_#{site_hash}=#{url};"
		cookie
	end

	# Tries to bruteforce a valid post_id
	#
	# @param min_post_id [Integer] The first post_id to bruteforce
	# @param max_post_id [Integer] The last post_id to bruteforce
	# @param login_cookie [String] If set perform the bruteforce as an authenticated user
	# @return [Integer,nil] The post id, nil when nothing found
	def wordpress_bruteforce_valid_post_id(min_post_id, max_post_id, login_cookie=nil)
		return nil if min_post_id > max_post_id
		range = Range.new(min_post_id, max_post_id)
		wordpress_helper_bruteforce_valid_post_id(range, false, login_cookie)
	end

	# Tries to bruteforce a valid post_id with comments enabled
	#
	# @param min_post_id [Integer] The first post_id to bruteforce
	# @param max_post_id [Integer] The last post_id to bruteforce
	# @param login_cookie [String] If set perform the bruteforce as an authenticated user
	# @return [Integer,nil] The post id, nil when nothing found
	def wordpress_bruteforce_valid_post_id_with_comments_enabled(min_post_id, max_post_id, login_cookie=nil)
		return nil if min_post_id > max_post_id
		range = Range.new(min_post_id, max_post_id)
		wordpress_helper_bruteforce_valid_post_id(range, true, login_cookie)
	end

	# Checks if the provided post has comments enabled
	#
	# @param post_id [Integer] The post ID to check
	# @param login_cookie [String] If set perform the check as an authenticated user
	# @return [String,nil] the HTTP response body of the post, nil otherwise
	def wordpress_post_id_comments_enabled?(post_id, login_cookie=nil)
		wordpress_helper_check_post_id(wordpress_url_post(post_id), true, login_cookie)
	end

	# Checks if the provided post has comments enabled
	#
	# @param url [String] The post url
	# @param login_cookie [String] If set perform the check as an authenticated user
	# @return [String,nil] the HTTP response body of the post, nil otherwise
	def wordpress_post_comments_enabled?(url, login_cookie=nil)
		wordpress_helper_check_post_id(url, true, login_cookie)
	end

	# Gets the post_id from a post body
	#
	# @param body [String] The body of a post
	# @return [String,nil] The post_id, nil when nothing found
	def get_post_id_from_body(body)
		return nil unless body
		body.match(/<body class="[^=]*postid-(\d+)[^=]*">/i)[1]
	end

	# Tries to get some Blog Posts via the RSS feed
	#
	# @param max_redirects [Integer] maximum redirects to follow
	# @return [Array<String>,nil] String Array with valid blog posts, nil on error
	def wordpress_get_all_blog_posts_via_feed(max_redirects = 10)
		vprint_status("#{peer} - Enumerating Blog posts...")
		blog_posts = []

		begin
			vprint_status("#{peer} - Locating wordpress feed...")
			res = send_request_cgi({
																 'uri'    => wordpress_url_rss,
																 'method' => 'GET'
														 })

			count = max_redirects

			# Follow redirects
			while (res.code == 301 || res.code == 302) and res.headers['Location'] and count != 0
				path = wordpress_helper_parse_location_header(res)
				return nil unless path

				vprint_status("#{peer} - Web server returned a #{res.code}...following to #{path}")
				res = send_request_cgi({
																	 'uri'    => path,
																	 'method' => 'GET'
															 })

				if res.code == 200
					vprint_status("#{peer} - Feed located at #{path}")
				else
					vprint_status("#{peer} - Returned a #{res.code}...")
				end
				count = count - 1
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			print_error("#{peer} - Unable to connect")
			return nil
		end

		if res.nil? or res.code != 200
			vprint_status("#{peer} - Did not recieve HTTP response for RSS feed")
			return blog_posts
		end

		# parse out links and place in array
		links = res.body.scan(/<link>([^<]+)<\/link>/i)

		if links.nil? or links.empty?
			vprint_status("#{peer} - Feed did not have any links present")
			return blog_posts
		end

		links.each do |link|
			path = path_from_uri(link[0])
			blog_posts << path if path
		end
		return blog_posts
	end

end
