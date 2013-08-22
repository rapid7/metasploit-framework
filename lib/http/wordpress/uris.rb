# -*- coding: binary -*-
module HTTP::Wordpress::URIs

	# Returns the Wordpress Login URL
	#
	# @return [String] Wordpress Login URL
	def wordpress_uri_login
		normalize_uri(target_uri.path, 'wp-login.php')
	end

	# Returns the Wordpress Post URL
	#
	# @param post_id Post ID
	# @return [String] Wordpress Post URL
	def wordpress_url_post(post_id)
		normalize_uri(target_uri.path) + "/?p=#{post_id}"
	end

	# Returns the Wordpress Author URL
	#
	# @param author_id Author ID
	# @return [String] Wordpress Author URL
	def wordpress_url_author(author_id)
		normalize_uri(target_uri.path) + "/?author=#{author_id}"
	end

end
