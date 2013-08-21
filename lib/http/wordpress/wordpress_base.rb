# -*- coding: binary -*-

###
#
# This module provides a way of interacting with wordpress installations
#
###

module HTTP
	class Wordpress

		# initializes a new Wordpress instance
		#
		# @param client The Metasploit module instance
		def initialize(client)
			@client = client
		end

		# Checks if the site is online and running wordpress
		#
		# @return [Boolean] Returns true if the site is online and running wordpress
		def wordpress_and_online?
			begin
				res = @client.send_request_cgi({
						'method' => 'GET',
						'uri' => @client.normalize_uri(@client.target_uri)
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
				print_error("Error connecting to #{@client.target_uri}")
				return false
			end

			return false
		end

		# Returns the Wordpress Login URL
		#
		# @return [String] Wordpress Login URL
		def wordpress_uri_login
			@client.normalize_uri(@client.target_uri.path, 'wp-login.php')
		end

		# Returns the Wordpress Post URL
		#
		# @param post_id Post ID
		# @return [String] Wordpress Post URL
		def wordpress_url_post(post_id)
			@client.normalize_uri(@client.target_uri.path) + "/?p=#{post_id}"
		end

		# Returns the Wordpress Author URL
		#
		# @param author_id Author ID
		# @return [String] Wordpress Author URL
		def wordpress_url_author(author_id)
			@client.normalize_uri(@client.target_uri.path) + "/?author=#{author_id}"
		end

		# performs a wordpress login
		#
		# @param user Username
		# @param pass Password
		# @return [String] the session cookie on successful login, nil otherwise
		def wordpress_login(user, pass)
			redirect = "#{@client.target_uri}#{Rex::Text.rand_text_alpha(8)}"
			res = @client.send_request_cgi({
					'method' => 'POST',
					'uri' => wordpress_uri_login,
					'data' => wordpress_helper_login_post_data(user, pass, redirect),
			}, 20)

			if res and res.code == 302 and res.headers['Location'] == redirect
				match = res.get_cookies.match(/(wordpress(?:_sec)?_logged_in_[^=]+=[^;]+);/i)
				if match
					# return wordpress login cookie
					return match[0]
				end
			end
			return nil
		end

		# Checks if the given user exists
		#
		# @param user Username
		# @return [Boolean] true if the user exists
		def wordpress_user_exists?(user)
			res = @client.send_request_cgi({
					'method' => 'POST',
					'uri' => wordpress_uri_login,
					'data' => wordpress_helper_login_post_data(user, 'x'),
			}, 20)

			exists = false
			if res and res.code == 200
				if res.body.to_s =~ /Incorrect password/ or
						res.body.to_s =~ /document\.getElementById\('user_pass'\)/
					exists = true
				else
					exists = false
				end
			end
			return exists
		end

		# Checks if the given userid exists
		#
		# @param user_id user_id
		# @return [String] the Username if it exists, nil otherwise
		def wordpress_userid_exists?(user_id)
			url = wordpress_url_author(user_id)
			res = @client.send_request_cgi({
					'method' => 'GET',
					'uri' => url
			})

			if res and res.code == 301
				uri = URI(res.headers['Location'])
				# try to extract username from location
				if uri.to_s =~ /\/author\/([^\/\b]+)\/?/i
					return $1
				end
				uri = "#{uri.path}?#{uri.query}"
				res = @client.send_request_cgi({
						'method' => 'GET',
						'uri' => uri
				})
			end

			if res.nil?
				print_error("#{@client.target_uri} - Error getting response.")
			elsif res.code == 200 and
					(res.body =~ /href="http[s]*:\/\/.*\/\?*author.+title="([[:print:]]+)" /i or
					res.body =~ /<body class="archive author author-(?:[^\s]+) author-(?:\d+)/i)
				return $1
			end
			return nil
		end

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

		private

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
					'uri' => @client.normalize_uri(@client.target_uri.path, 'wp-comments-post.php'),
					'method' => 'POST'
			}
			options.merge!({'vars_post' => vars_post})
			options.merge!({'cookie' => login_cookie}) if login_cookie
			res = @client.send_request_cgi(options)
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
			res = @client.send_request_cgi(options)
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
end
