# -*- coding: binary -*-
###
#
# This mixin provides helper methods for Cacti
#
###

module Msf
module Exploit::Cacti

  include Msf::Exploit::Remote::HttpClient

  class CactiError < StandardError; end
  class CactiNotFoundError < CactiError; end
  class CactiVersionNotFoundError < CactiError; end
  class CactiNoAccessError < CactiError; end
  class CactiCsrfNotFoundError < CactiError; end
  class CactiLoginError < CactiError; end

  # Extract the version number from an HTML response
  #
  # @param html [Nokogiri::HTML::Document] The HTML response
  # @return [String] The version number
  # @raise [CactiNotFoundError] If the web server is not running Cacti
  # @raise [CactiVersionNotFoundError] If the version string was not found
  def parse_version(html)
    # This will return an empty string if there is no match
    version_str = html.xpath('//div[@class="versionInfo"]').text
    unless version_str.include?('The Cacti Group')
      raise CactiNotFoundError, 'The web server is not running Cacti'
    end
    unless version_str.match(/Version (?<version>\d{1,2}[.]\d{1,2}[.]\d{1,2})/)
      raise CactiVersionNotFoundError, 'Could not detect the version'
    end

    Regexp.last_match[:version]
  end

  # Extract the CSRF token from an HTML response
  #
  # @param html [Nokogiri::HTML::Document] The HTML response to parse
  # @return [String] The CSRF token
  def parse_csrf_token(html)
    html.xpath('//form/input[@name="__csrf_magic"]/@value').text
  end

  # Get the CSRF token by querying the `index.php` web page and extracting it
  # from the response.
  #
  # @return [String] The CSRF token
  # @raise [CactiNoAccessError] If the server is unreachable
  # @raise [CactiCsrfNotFoundError] If it was not possible to get the CSRF token
  def get_csrf_token
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'method' => 'GET',
      'keep_cookies' => true
    )
    raise CactiNoAccessError, 'Could not access `index.php` - no response' if res.nil?

    html = res.get_html_document
    csrf_token = parse_csrf_token(html)
    raise CactiCsrfNotFoundError, 'Unable to get the CSRF token' if csrf_token.empty?

    csrf_token
  end

  # Log in to Cacti. It will take care of grabbing the CSRF token if not provided.
  #
  # @param username [String] The username
  # @param password [String] The password
  # @raise [CactiNoAccessError] If the server is unreachable
  # @raise [CactiCsrfNotFoundError] If the CSRF token was not provided and it was not possible to retrieve it
  # @raise [CactiLoginError] If the login failed
  def do_login(username, password, csrf_token: nil)
    if csrf_token.blank?
      print_status('Getting the CSRF token to login')
      begin
        csrf_token = get_csrf_token
      rescue CactiError => e
        raise CactiLoginError, "Unable to login: #{e.class} - #{e}"
      end

      vprint_good("CSRF token: #{csrf_token}")
    end

    print_status("Attempting login with user `#{username}` and password `#{password}`")
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'method' => 'POST',
      'keep_cookies' => true,
      'vars_post' => {
        '__csrf_magic' => csrf_token,
        'action' => 'login',
        'login_username' => username,
        'login_password' => password
      }
    )
    raise CactiNoAccessError, 'Could not login - no response' if res.nil?
    raise CactiLoginError, "Login failure - unexpected HTTP response code: #{res.code}" unless res.code == 302

    print_good('Logged in')

    nil
  end

end
end
