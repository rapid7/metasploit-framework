# -*- coding: binary -*-

module Msf::HTTP::Wordpress::Version

  # Used to check if the version is correct: must contain at least one dot
  WORDPRESS_VERSION_PATTERN = '([^\r\n"\']+\.[^\r\n"\']+)'

  # Extracts the Wordpress version information from various sources
  #
  # @return [String,nil] Wordpress version if found, nil otherwise
  def wordpress_version
    # detect version from generator
    version = wordpress_version_helper(normalize_uri(target_uri.path), /<meta name="generator" content="WordPress #{WORDPRESS_VERSION_PATTERN}" \/>/i)
    return version if version

    # detect version from readme
    version = wordpress_version_helper(wordpress_url_readme, /<br \/>\sversion #{WORDPRESS_VERSION_PATTERN}/i)
    return version if version

    # detect version from rss
    version = wordpress_version_helper(wordpress_url_rss, /<generator>http:\/\/wordpress.org\/\?v=#{WORDPRESS_VERSION_PATTERN}<\/generator>/i)
    return version if version

    # detect version from rdf
    version = wordpress_version_helper(wordpress_url_rdf, /<admin:generatorAgent rdf:resource="http:\/\/wordpress.org\/\?v=#{WORDPRESS_VERSION_PATTERN}" \/>/i)
    return version if version

    # detect version from atom
    version = wordpress_version_helper(wordpress_url_atom, /<generator uri="http:\/\/wordpress.org\/" version="#{WORDPRESS_VERSION_PATTERN}">WordPress<\/generator>/i)
    return version if version

    # detect version from sitemap
    version = wordpress_version_helper(wordpress_url_sitemap, /generator="wordpress\/#{WORDPRESS_VERSION_PATTERN}"/i)
    return version if version

    # detect version from opml
    version = wordpress_version_helper(wordpress_url_opml, /generator="wordpress\/#{WORDPRESS_VERSION_PATTERN}"/i)
    return version if version

    nil
  end

  # Checks a readme for a vulnerable version
  #
  # @param [String] plugin_name The name of the plugin
  # @param [String] fixed_version The version the vulnerability was fixed in
  # @param [String] vuln_introduced_version Optional, the version the vulnerability was introduced
  #
  # @return [ Msf::Exploit::CheckCode ]
  def check_plugin_version_from_readme(plugin_name, fixed_version, vuln_introduced_version = nil)
    check_version_from_readme(:plugin, plugin_name, fixed_version, vuln_introduced_version)
  end

  # Checks a readme for a vulnerable version
  #
  # @param [String] theme_name The name of the theme
  # @param [String] fixed_version The version the vulnerability was fixed in
  # @param [String] vuln_introduced_version Optional, the version the vulnerability was introduced
  #
  # @return [ Msf::Exploit::CheckCode ]
  def check_theme_version_from_readme(theme_name, fixed_version, vuln_introduced_version = nil)
    check_version_from_readme(:theme, theme_name, fixed_version, vuln_introduced_version)
  end

  private

  def wordpress_version_helper(url, regex)
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => url
    )
    if res
      match = res.body.match(regex)
      return match[1] if match
    end

    nil
  end

  def check_version_from_readme(type, name, fixed_version, vuln_introduced_version = nil)
    case type
    when :plugin
      folder = 'plugins'
    when :theme
      folder = 'themes'
    else
      fail("Unknown readme type #{type}")
    end

    readme_url = normalize_uri(target_uri.path, wp_content_dir, folder, name, 'readme.txt')
    res = send_request_cgi(
      'uri'    => readme_url,
      'method' => 'GET'
    )
    # no readme.txt present
    return Msf::Exploit::CheckCode::Unknown if res.nil? || res.code != 200

    # try to extract version from readme
    # Example line:
    # Stable tag: 2.6.6
    version = res.body.to_s[/stable tag: ([^\r\n"\']+\.[^\r\n"\']+)/i, 1]

    # readme present, but no version number
    return Msf::Exploit::CheckCode::Detected if version.nil?

    vprint_status("#{peer} - Found version #{version} of the #{type}")

    # Version older than fixed version
    if Gem::Version.new(version) < Gem::Version.new(fixed_version)
      if vuln_introduced_version.nil?
        # All versions are vulnerable
        return Msf::Exploit::CheckCode::Appears
      # vuln_introduced_version provided, check if version is newer
      elsif Gem::Version.new(version) >= Gem::Version.new(vuln_introduced_version)
        return Msf::Exploit::CheckCode::Appears
      else
        # Not in range, nut vulnerable
        return Msf::Exploit::CheckCode::Safe
      end
    # version newer than fixed version
    else
      return Msf::Exploit::CheckCode::Safe
    end
  end
end
