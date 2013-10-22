# -*- coding: binary -*-
module Msf::HTTP::Wordpress::URIs

  # Returns the Wordpress Login URL
  #
  # @return [String] Wordpress Login URL
  def wordpress_url_login
    normalize_uri(target_uri.path, 'wp-login.php')
  end

  # Returns the Wordpress Post URL
  #
  # @param post_id [Integer] Post ID
  # @return [String] Wordpress Post URL
  def wordpress_url_post(post_id)
    normalize_uri(target_uri.path, "?p=#{post_id}")
  end

  # Returns the Wordpress Author URL
  #
  # @param author_id [Integer] Author ID
  # @return [String] Wordpress Author URL
  def wordpress_url_author(author_id)
    normalize_uri(target_uri.path, "?author=#{author_id}")
  end

  # Returns the Wordpress RSS feed URL
  #
  # @return [String] Wordpress RSS URL
  def wordpress_url_rss
    normalize_uri(target_uri.path, '?feed=rss2')
  end

  # Returns the Wordpress RDF feed URL
  #
  # @return [String] Wordpress RDF URL
  def wordpress_url_rdf
    normalize_uri(target_uri.path, 'feed/rdf/')
  end

  # Returns the Wordpress ATOM feed URL
  #
  # @return [String] Wordpress ATOM URL
  def wordpress_url_atom
    normalize_uri(target_uri.path, 'feed/atom/')
  end

  # Returns the Wordpress Readme file URL
  #
  # @return [String] Wordpress Readme file URL
  def wordpress_url_readme
    normalize_uri(target_uri.path, 'readme.html')
  end

  # Returns the Wordpress Sitemap URL
  #
  # @return [String] Wordpress Sitemap URL
  def wordpress_url_sitemap
    normalize_uri(target_uri.path, 'sitemap.xml')
  end

  # Returns the Wordpress OPML URL
  #
  # @return [String] Wordpress OPML URL
  def wordpress_url_opml
    normalize_uri(target_uri.path, 'wp-links-opml.php')
  end

end
