# -*- coding: binary -*-

#
# This mixin provides helpers to interact with pgAdmin. It provides methods to:
# - authenticate
# - obtain the CSRF token,
# - check the version of pgAdmin.
#
module Msf
  module Exploit::PgAdmin
    include Msf::Exploit::Remote::HttpClient

    def auth_required?
      res = send_request_cgi('uri' => normalize_uri(target_uri.path), 'keep_cookies' => true)
      if res&.code == 302 && res.headers['Location']['login']
        return true
      end
      false
    end

    def get_version
      if auth_required?
        res = send_request_cgi('uri' => normalize_uri(target_uri.path, 'login'), 'keep_cookies' => true)
      else
        res = send_request_cgi('uri' => normalize_uri(target_uri.path, 'browser/'), 'keep_cookies' => true)
      end
      html_document = res&.get_html_document
      return unless html_document&.xpath('//title').text == 'pgAdmin 4'

      # there's multiple links in the HTML that expose the version number in the [X]XYYZZ,
      # see: https://github.com/pgadmin-org/pgadmin4/blob/053b1e3d693db987d1c947e1cb34daf842e387b7/web/version.py#L27
      versioned_link = html_document.xpath('//link').find { |link| link['href'] =~ /\?ver=(\d?\d)(\d\d)(\d\d)/ }
      return unless versioned_link

      Rex::Version.new("#{Regexp.last_match(1).to_i}.#{Regexp.last_match(2).to_i}.#{Regexp.last_match(3).to_i}")
    end

    def check_version(patched_version, low_bound = 0)
      version = get_version
      return Msf::Exploit::CheckCode::Unknown('Unable to determine the target version') unless version
      return Msf::Exploit::CheckCode::Safe("pgAdmin version #{version} is not affected") if version >= Rex::Version.new(patched_version) || version < Rex::Version.new(low_bound)

      Msf::Exploit::CheckCode::Appears("pgAdmin version #{version} is affected")
    end

    def csrf_token
      return @csrf_token if @csrf_token

      if auth_required?
        res = send_request_cgi('uri' => normalize_uri(target_uri.path, 'login'), 'keep_cookies' => true)
        set_csrf_token_from_login_page(res)
      else
        res = send_request_cgi('uri' => normalize_uri(target_uri.path, 'browser/js/utils.js'), 'keep_cookies' => true)
        set_csrf_token_from_config(res)
      end
      fail_with(Failure::UnexpectedReply, 'Failed to obtain the CSRF token') unless @csrf_token
      @csrf_token
    end

    def set_csrf_token_from_config(res)

      # The CSRF token should be inside a java script tag, inside a function called window.renderSecurityPage and should look like:
      # ImQzYTQ0YzAzOGMyY2YwZWNkMWRkY2Q4ODdhMTA5MGM3YzI5ZTYzY2Ii.Z_6Kdw.XP2eOIJ26MikqG5J8J8W1bDPMpQ
      if res&.code == 200 && res.body =~ /csrfToken": "([\w+.-]+)"/
        @csrf_token = Regexp.last_match(1)
        # at some point between v7.0 and 7.7 the token format changed
      else
        @csrf_token = res&.body.scan(/pgAdmin\['csrf_token'\]\s*=\s*'([^']+)'/)&.flatten&.first
      end
    end

    def set_csrf_token_from_login_page(res)
      if res&.code == 200 && res.body =~ /csrfToken": "([\w+.-]+)"/
        @csrf_token = Regexp.last_match(1)
        # at some point between v7.0 and 7.7 the token format changed
      elsif (element = res.get_html_document.xpath("//input[@id='csrf_token']")&.first)
        @csrf_token = element['value']
      end
    end

    def authenticate(username, password)
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'authenticate/login'),
        'method' => 'POST',
        'keep_cookies' => true,
        'vars_post' => {
          'csrf_token' => csrf_token,
          'email' => username,
          'password' => password,
          'language' => 'en',
          'internal_button' => 'Login'
        }
      })

      unless res&.code == 302 && res&.headers&.[]('Location') != normalize_uri(target_uri.path, 'login')
        fail_with(Msf::Exploit::Failure::NoAccess, 'Failed to authenticate to pgAdmin')
      end

      print_good('Successfully authenticated to pgAdmin')
      res
    end
  end
end
