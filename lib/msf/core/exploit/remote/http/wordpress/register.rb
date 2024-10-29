# -*- coding: binary -*-

module Msf::Exploit::Remote::HTTP::Wordpress::Register
  # performs a wordpress registration
  #
  # @param user [String] Username
  # @param email [String] Email Address
  # @param timeout [Integer] The maximum number of seconds to wait before the request times out
  # @return [Bool] registration request success status
  def wordpress_register(user, email, timeout = 20)
    redirect = "#{target_uri}#{Rex::Text.rand_text_alpha(8)}"
    res = send_request_cgi({
        'method' => 'POST',
        'uri' => wordpress_url_login,
        'vars_get' => {'action' => 'register'},
        'vars_post' => wordpress_helper_register_post_data(user, email, redirect)
    }, timeout)
    res && res.redirect? && res.redirection && res.redirection.to_s == redirect
  end
end
