# -*- coding: binary -*-

module Msf::HTTP::Wordpress::Version

  # Extracts the Wordpress version information from various sources
  #
  # @return [String,nil] Wordpress version if found, nil otherwise
  def wordpress_version
    # detect version from generator
    version = wordpress_version_helper(normalize_uri(target_uri.path), /<meta name="generator" content="WordPress #{wordpress_version_pattern}" \/>/i)
    return version if version

    # detect version from readme
    version = wordpress_version_helper(wordpress_url_readme, /<br \/>\sversion #{wordpress_version_pattern}/i)
    return version if version

    # detect version from rss
    version = wordpress_version_helper(wordpress_url_rss, /<generator>http:\/\/wordpress.org\/\?v=#{wordpress_version_pattern}<\/generator>/i)
    return version if version

    # detect version from rdf
    version = wordpress_version_helper(wordpress_url_rdf, /<admin:generatorAgent rdf:resource="http:\/\/wordpress.org\/\?v=#{wordpress_version_pattern}" \/>/i)
    return version if version

    # detect version from atom
    version = wordpress_version_helper(wordpress_url_atom, /<generator uri="http:\/\/wordpress.org\/" version="#{wordpress_version_pattern}">WordPress<\/generator>/i)
    return version if version

    # detect version from sitemap
    version = wordpress_version_helper(wordpress_url_sitemap, /generator="wordpress\/#{wordpress_version_pattern}"/i)
    return version if version

    # detect version from opml
    version = wordpress_version_helper(wordpress_url_opml, /generator="wordpress\/#{wordpress_version_pattern}"/i)
    return version if version

    nil
  end

  private

  # Used to check if the version is correct: must contain at least one dot.
  #
  # @return [ String ]
  def wordpress_version_pattern
    '([^\r\n"\']+\.[^\r\n"\']+)'
  end

  def wordpress_version_helper(url, regex)
    res = send_request_cgi({
        'method' => 'GET',
        'uri' => url
    })
    if res
      match = res.body.match(regex)
      if match
        return match[1]
      end
    end

    nil
  end

end
