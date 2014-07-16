# -*- coding: binary -*-
module Msf::HTTP::Wordpress::Login

  # performs a wordpress login
  #
  # @param user [String] Username
  # @param pass [String] Password
  # @return [String,nil] the session cookies as a single string on successful login, nil otherwise
  def wordpress_login(user, pass)
    redirect = "#{target_uri}#{Rex::Text.rand_text_alpha(8)}"
    res = send_request_cgi({
        'method' => 'POST',
        'uri' => wordpress_url_login,
        'vars_post' => wordpress_helper_login_post_data(user, pass, redirect)
    })

    if res and (res.code == 301 or res.code == 302) and res.headers['Location'] == redirect
      cookies = res.get_cookies
      # Check if a valid wordpress cookie is returned
      return cookies if cookies =~ /wordpress(?:_sec)?_logged_in_[^=]+=[^;]+;/i ||
        cookies =~ /wordpress(?:user|pass)_[^=]+=[^;]+;/i ||
        cookies =~ /wordpress_[a-z0-9]+=[^;]+;/i
    end

    return nil
  end

end
