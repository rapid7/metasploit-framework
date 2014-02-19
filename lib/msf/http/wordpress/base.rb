# -*- coding: binary -*-

module Msf::HTTP::Wordpress::Base

  # Checks if the site is online and running wordpress
  #
  # @return [Rex::Proto::Http::Response,nil] Returns the HTTP response if the site is online and running wordpress, nil otherwise
  def wordpress_and_online?
    begin
      res = send_request_cgi({
          'method' => 'GET',
          'uri' => normalize_uri(target_uri.path)
      })
      return res if res and
          res.code == 200 and
          (
            res.body =~ /["'][^"']*\/wp-content\/[^"']*["']/i or
            res.body =~ /<link rel=["']wlwmanifest["'].*href=["'].*\/wp-includes\/wlwmanifest\.xml["'] \/>/i or
            res.body =~ /<link rel=["']pingback["'].*href=["'].*\/xmlrpc\.php["'] \/>/i
          )
      return nil
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      print_error("#{peer} - Error connecting to #{target_uri}")
      return nil
    end
  end

end
